#!/usr/bin/env python3
"""
Minimal cleaning + SMOTE balancing of the raw honeypot dataset.
Only does what MUST happen before the notebooks: removes junk, fixes types, balances classes.
Real data science (feature engineering, EDA, encoding) stays in the notebooks.

Input:  honeypot_dataset_full.csv  (raw ES export, ~2.6M rows)
Output: honeypot_dataset.csv       (cleaned + balanced)

Usage:
    pip install pandas scikit-learn imbalanced-learn
    python clean_and_balance.py
"""

import pandas as pd
import numpy as np
import os
from collections import Counter

INPUT_FILE = "honeypot_dataset_full.csv"
OUTPUT_FILE = "honeypot_dataset.csv"


def main():
    print("=" * 60)
    print("  STEP 1: Load & Minimal Clean")
    print("=" * 60)

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"  Raw shape: {df.shape}")

    # --- Drop rows where log_type or is_attack is missing ---
    before = len(df)
    df.dropna(subset=["log_type", "is_attack"], inplace=True)
    dropped = before - len(df)
    if dropped:
        print(f"  Dropped {dropped:,} rows with missing log_type/is_attack")

    # --- Drop exact duplicate rows ---
    before = len(df)
    df.drop_duplicates(inplace=True)
    dropped = before - len(df)
    print(f"  Dropped {dropped:,} exact duplicate rows")

    # --- Drop 100% NaN columns ---
    all_nan = [c for c in df.columns if df[c].isna().all()]
    if all_nan:
        df.drop(columns=all_nan, inplace=True)
        print(f"  Dropped 100% NaN columns: {all_nan}")

    # --- Fix boolean columns stored as strings ---
    bool_cols = ["is_attack", "is_internal", "is_known_device", "is_known_topic",
                 "is_known_path", "login_success", "login_attempt", "retain"]
    for col in bool_cols:
        if col in df.columns:
            df[col] = df[col].map({
                "true": True, "false": False, "True": True, "False": False,
                True: True, False: False, 1: True, 0: False, "1": True, "0": False,
            })

    # --- Fix numeric columns ---
    numeric_cols = [
        "src_port", "dst_port", "bytes_sent", "bytes_received",
        "payload_size", "body_size", "qos", "packet_count", "pps",
        "window_seconds", "http_status_code",
        "msg_rate_per_min", "req_rate_per_min",
        "session_msg_count", "session_topic_count",
        "session_req_count", "session_endpoint_count",
        "session_path_count", "session_duration_s",
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    print(f"\n  Cleaned shape: {df.shape}")
    print(f"\n  Class distribution BEFORE balancing:")
    print(f"    is_attack: {df['is_attack'].value_counts().to_dict()}")
    print(f"    attack_type:")
    for cls, cnt in df["attack_type"].value_counts().items():
        print(f"      {cls:20s}: {cnt:>10,}")

    # ── STEP 2: Downsample benign + SMOTE minority ─────────────────
    print(f"\n{'=' * 60}")
    print("  STEP 2: Downsample Benign + SMOTE Attack Classes")
    print("=" * 60)

    from imblearn.over_sampling import SMOTE

    # Separate benign and attack
    df_benign = df[df["attack_type"] == "benign"]
    df_attack = df[df["attack_type"] != "benign"]

    # Merge very rare classes (< 30 samples) into parent categories
    merge_map = {
        "malware_download": "exploit",
        "post_exploit": "exploit",
    }
    df_attack = df_attack.copy()
    df_attack["attack_type"] = df_attack["attack_type"].replace(merge_map)

    attack_counts = df_attack["attack_type"].value_counts()
    print(f"\n  Attack classes (after merging rare):")
    for cls, cnt in attack_counts.items():
        print(f"    {cls:20s}: {cnt:>10,}")

    # Downsample benign: keep ~50k per protocol for representativeness
    # Total benign target: ~150k (roughly 2x total attacks after SMOTE)
    benign_per_protocol = 25_000
    benign_samples = []
    for proto in df_benign["log_type"].unique():
        proto_df = df_benign[df_benign["log_type"] == proto]
        n = min(len(proto_df), benign_per_protocol)
        benign_samples.append(proto_df.sample(n=n, random_state=42))
    df_benign_down = pd.concat(benign_samples, ignore_index=True)
    print(f"\n  Benign downsampled: {len(df_benign):,} → {len(df_benign_down):,}")
    print(f"    Per protocol: {df_benign_down['log_type'].value_counts().to_dict()}")

    # Combine for SMOTE
    df_combined = pd.concat([df_benign_down, df_attack], ignore_index=True)

    # Select numeric features for SMOTE
    smote_features = [
        "bytes_sent", "bytes_received", "src_port", "dst_port",
        "payload_size", "body_size", "qos",
        "msg_rate_per_min", "req_rate_per_min",
        "session_msg_count", "session_topic_count",
        "session_req_count", "session_endpoint_count",
        "session_path_count", "session_duration_s",
        "http_status_code", "packet_count", "pps", "window_seconds",
    ]
    smote_features = [c for c in smote_features if c in df_combined.columns]

    # Encode log_type and protocol for SMOTE
    cat_for_smote = ["log_type", "protocol"]
    cat_mappings = {}
    for col in cat_for_smote:
        if col in df_combined.columns:
            codes, uniques = pd.factorize(df_combined[col])
            df_combined[f"__{col}_code"] = codes
            cat_mappings[col] = dict(enumerate(uniques))
            smote_features.append(f"__{col}_code")

    X = df_combined[smote_features].fillna(0).values
    y = df_combined["attack_type"].values

    class_counts = Counter(y)
    target_per_attack = 12_000

    sampling_strategy = {}
    for cls, cnt in class_counts.items():
        if cls == "benign":
            sampling_strategy[cls] = cnt
        else:
            sampling_strategy[cls] = max(cnt, target_per_attack)

    print(f"\n  SMOTE targets:")
    for cls, target in sorted(sampling_strategy.items(), key=lambda x: -x[1]):
        current = class_counts[cls]
        change = "→" if target > current else "="
        print(f"    {cls:20s}: {current:>10,} {change} {target:>10,}")

    min_class = min(class_counts.values())
    k = min(5, min_class - 1)
    k = max(1, k)
    print(f"\n  SMOTE k_neighbors={k} (smallest class: {min_class})")
    print("  Running SMOTE...")

    smote = SMOTE(sampling_strategy=sampling_strategy, k_neighbors=k, random_state=42)
    X_res, y_res = smote.fit_resample(X, y)
    print(f"  Done: {len(X):,} → {len(X_res):,} rows")

    # Build balanced DataFrame
    df_balanced = pd.DataFrame(X_res, columns=smote_features)
    df_balanced["attack_type"] = y_res
    df_balanced["is_attack"] = (y_res != "benign")

    # Decode categorical codes back
    for col in cat_for_smote:
        code_col = f"__{col}_code"
        if code_col in df_balanced.columns:
            mapping = cat_mappings[col]
            df_balanced[col] = df_balanced[code_col].round().astype(int).map(mapping)
            df_balanced[col].fillna(df_combined[col].mode()[0], inplace=True)
            df_balanced.drop(columns=[code_col], inplace=True)

    # Restore non-numeric columns from original data for real rows
    n_original = len(df_combined)
    non_smote_cols = [c for c in df_combined.columns
                      if c not in smote_features
                      and c not in ["attack_type", "is_attack"]
                      and c not in cat_for_smote
                      and not c.startswith("__")]

    for col in non_smote_cols:
        df_balanced[col] = np.nan
        if col in df_combined.columns:
            df_balanced.loc[:n_original - 1, col] = df_combined[col].values

    # For synthetic rows: mark string cols
    for col in non_smote_cols:
        if df_balanced[col].dtype == object:
            df_balanced[col].fillna("synthetic", inplace=True)

    # Drop temp columns
    for col in list(df_balanced.columns):
        if col.startswith("__"):
            df_balanced.drop(columns=[col], inplace=True)

    # Shuffle
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n  Final shape: {df_balanced.shape}")
    print(f"\n  Class distribution AFTER balancing:")
    print(f"    is_attack: {df_balanced['is_attack'].value_counts().to_dict()}")
    print(f"    attack_type:")
    for cls, cnt in df_balanced["attack_type"].value_counts().items():
        print(f"      {cls:20s}: {cnt:>10,}")

    # ── STEP 3: Save ────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("  STEP 3: Save")
    print("=" * 60)

    df_balanced.to_csv(OUTPUT_FILE, index=False)
    size_mb = round(os.path.getsize(OUTPUT_FILE) / 1024 / 1024, 1)
    print(f"  Saved: {OUTPUT_FILE} ({size_mb} MB)")
    print(f"  Rows:  {len(df_balanced):,}")
    print(f"  Cols:  {df_balanced.shape[1]}")
    print(f"\nDone. Load with: df = pd.read_csv('{OUTPUT_FILE}')")


if __name__ == "__main__":
    main()
