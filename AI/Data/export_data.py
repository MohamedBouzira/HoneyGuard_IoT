#!/usr/bin/env python3
"""
Export ALL honeypot data from Elasticsearch → unified CSV for AI training.
Handles ~20GB of data using the scroll API and chunked CSV writing.

Run locally with SSH tunnel open:
    ssh -L 9200:172.22.0.2:9200 honeypot-gcp@35.205.229.51 -p 22222

Usage:
    pip install elasticsearch pandas
    python export_data.py
"""

import sys
import time
import os
import pandas as pd
from elasticsearch import Elasticsearch

# ── CONFIG ───────────────────────────────────────────────────────
ES_HOST      = "http://localhost:9200"
OUTPUT_FILE  = "honeypot_dataset_full.csv"
SCROLL_SIZE  = 5000        # docs per scroll page (tune down if ES runs out of memory)
SCROLL_TTL   = "5m"        # keep scroll context alive for 5 minutes between pages
CHUNK_ROWS   = 50_000      # flush to CSV every N rows (keeps RAM low)

# The 6 index patterns
INDEX_PATTERNS = [
    "honeypot-mqtt-*",
    "honeypot-http-*",
    "honeypot-coap-*",
    "honeypot-cowrie-*",
    "honeypot-network-*",
    "honeypot-platform-*",
]

# ── 13 COMMON FIELDS (present in all 6 indices) ─────────────────
COMMON_FIELDS = [
    "@timestamp", "log_type", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes_sent", "bytes_received", "is_internal",
    "is_known_device", "is_attack", "attack_type", "session_id",
]

# ── PROTOCOL-SPECIFIC FIELDS ────────────────────────────────────
MQTT_FIELDS = [
    "mqtt_action", "client_id", "topic", "payload_size", "qos", "retain",
    "is_known_topic", "session_msg_count", "session_topic_count",
    "msg_rate_per_min", "session_duration_s",
]

HTTP_FIELDS = [
    "http_method", "http_endpoint", "http_status_code", "user_agent",
    "body_size", "session_req_count", "session_endpoint_count",
    "req_rate_per_min", "session_duration_s",
]

COAP_FIELDS = [
    "coap_method", "coap_path", "coap_response_code", "is_known_path",
    "payload_size", "session_req_count", "session_path_count",
    "req_rate_per_min", "session_duration_s",
]

COWRIE_FIELDS = [
    "eventid", "username", "password", "command",
    "session_duration_s", "login_success", "src_ip",
]

NETWORK_FIELDS = [
    "attack_name", "packet_count", "pps", "scanned_ports", "window_seconds",
]

PLATFORM_FIELDS = [
    "http_method", "http_endpoint", "http_status_code", "user_agent",
    "body_size", "login_attempt", "login_success", "username_tried",
    "session_req_count", "session_endpoint_count",
    "req_rate_per_min", "session_duration_s",
]

ALL_FIELDS = list(set(
    COMMON_FIELDS + MQTT_FIELDS + HTTP_FIELDS + COAP_FIELDS +
    COWRIE_FIELDS + NETWORK_FIELDS + PLATFORM_FIELDS
))

# Columns to drop (not useful for training)
DROP_COLS = [
    "session_id", "payload", "body", "scanned_ports",
    "password", "password_tried",
    "@version", "tags", "input", "log_source", "content_type",
    "http_version", "file_url",
]

# Final column order
COLUMN_ORDER = [
    "@timestamp", "log_type", "protocol",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "bytes_sent", "bytes_received",
    "is_attack", "attack_type",
    "is_internal", "is_known_device",
    "mqtt_action", "client_id", "topic", "payload_size",
    "qos", "retain", "is_known_topic",
    "msg_rate_per_min", "session_msg_count", "session_topic_count",
    "http_method", "http_endpoint", "http_status_code",
    "user_agent", "body_size",
    "req_rate_per_min", "session_req_count", "session_endpoint_count",
    "coap_method", "coap_path", "coap_response_code", "is_known_path",
    "session_path_count",
    "eventid", "username", "command", "login_success",
    "attack_name", "packet_count", "pps", "window_seconds",
    "login_attempt", "username_tried",
    "session_duration_s",
]


# ── HELPERS ──────────────────────────────────────────────────────
def fmt_num(n):
    return f"{n:,}"


def fmt_size(path):
    """Return human-readable file size."""
    if not os.path.exists(path):
        return "0 B"
    size = os.path.getsize(path)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# ── STEP 1: Connect ──────────────────────────────────────────────
def connect_es():
    es = Elasticsearch(ES_HOST, verify_certs=False)
    try:
        info = es.info()
        version = info["version"]["number"]
        print(f"Connected to Elasticsearch {version}")
    except Exception as e:
        print(f"ERROR: Cannot connect to Elasticsearch at {ES_HOST}")
        print(f"  Reason: {e}")
        print("Make sure your SSH tunnel is open:")
        print("  ssh -L 9200:172.22.0.2:9200 honeypot-gcp@35.205.229.51 -p 22222")
        sys.exit(1)
    return es


# ── STEP 2: Index stats ──────────────────────────────────────────
def show_index_stats(es):
    print("\n── Index Statistics ──")
    total = 0
    for pattern in INDEX_PATTERNS:
        try:
            count = es.count(index=pattern)["count"]
            total += count
            print(f"  {pattern:30s} → {fmt_num(count):>12} docs")
        except Exception as e:
            print(f"  {pattern:30s} → ERROR: {e}")
    print(f"  {'TOTAL':30s} → {fmt_num(total):>12} docs")
    print()
    return total


# ── STEP 3: Normalise a batch of raw ES docs ─────────────────────
def normalise_batch(docs, index_pattern):
    """Convert a list of ES _source dicts into a clean DataFrame chunk."""
    df = pd.DataFrame(docs)

    # Ensure all expected columns exist
    for col in ALL_FIELDS:
        if col not in df.columns:
            df[col] = pd.NA

    # Tag which index produced this row
    if "log_type" not in df.columns or df["log_type"].isna().all():
        tag = index_pattern.replace("honeypot-", "").replace("-*", "")
        df["log_type"] = tag

    # Types: booleans
    bool_cols = [
        "is_attack", "is_internal", "is_known_device", "is_known_topic",
        "is_known_path", "login_attempt", "login_success", "retain",
    ]
    for col in bool_cols:
        if col in df.columns:
            df[col] = df[col].map(
                {"true": True, "false": False, True: True, False: False,
                 1: True, 0: False, "1": True, "0": False}
            )

    # Types: numerics
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

    # Drop unwanted columns
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # Keep ONLY columns in COLUMN_ORDER — drop any extras from ES
    df = df[[c for c in COLUMN_ORDER if c in df.columns]]

    return df


# ── STEP 4: Scroll ALL docs from one index, flush to CSV ─────────
def scroll_index(es, index_pattern, writer_state):
    """
    Scroll through every document in index_pattern.
    writer_state = {"total": int, "header_written": bool, "buffer": []}
    Returns number of docs exported from this index.
    """
    # Initial search
    try:
        resp = es.search(
            index=index_pattern,
            scroll=SCROLL_TTL,
            size=SCROLL_SIZE,
            query={"match_all": {}},
            _source=True,
        )
    except Exception as e:
        print(f"  ERROR opening scroll on {index_pattern}: {e}")
        return 0

    scroll_id = resp["_scroll_id"]
    hits      = resp["hits"]["hits"]
    index_count = 0

    while hits:
        docs = [h["_source"] for h in hits]
        writer_state["buffer"].extend(docs)
        index_count          += len(docs)
        writer_state["total"] += len(docs)

        # Flush buffer to CSV every CHUNK_ROWS rows
        if len(writer_state["buffer"]) >= CHUNK_ROWS:
            _flush(writer_state, index_pattern)

        # Progress line (overwrite in place)
        print(
            f"\r  {index_pattern:30s} → {fmt_num(index_count):>10} docs "
            f"| total: {fmt_num(writer_state['total']):>12} "
            f"| file: {fmt_size(OUTPUT_FILE):>9}",
            end="", flush=True,
        )

        # Next scroll page
        try:
            resp   = es.scroll(scroll_id=scroll_id, scroll=SCROLL_TTL)
            scroll_id = resp["_scroll_id"]
            hits   = resp["hits"]["hits"]
        except Exception as e:
            print(f"\n  WARNING: scroll error on {index_pattern}: {e}")
            break

    # Clear scroll context to free ES resources
    try:
        es.clear_scroll(scroll_id=scroll_id)
    except Exception:
        pass

    # Flush any remaining docs in buffer that belong to this index
    if writer_state["buffer"]:
        _flush(writer_state, index_pattern)

    print()  # newline after the \r progress line
    return index_count


def _flush(writer_state, index_pattern):
    """Normalise buffered docs and append to CSV."""
    import csv
    df = normalise_batch(writer_state["buffer"], index_pattern)
    writer_state["buffer"] = []

    mode   = "a"
    header = not writer_state["header_written"]
    df.to_csv(OUTPUT_FILE, mode=mode, header=header, index=False,
              quoting=csv.QUOTE_NONNUMERIC)
    if header:
        writer_state["header_written"] = True


# ── MAIN ─────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Honeypot Full Data Export → CSV")
    print("=" * 60)

    es = connect_es()
    total_es = show_index_stats(es)

    # Remove old output file so we start fresh
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)
        print(f"Removed existing {OUTPUT_FILE}\n")

    writer_state = {
        "total":          0,
        "header_written": False,
        "buffer":         [],
    }

    t0 = time.time()
    print("── Scrolling all indices ──")

    per_index_counts = {}
    for pattern in INDEX_PATTERNS:
        n = scroll_index(es, pattern, writer_state)
        per_index_counts[pattern] = n

    elapsed = time.time() - t0

    # ── Final summary ──
    print("\n" + "=" * 60)
    print("  EXPORT COMPLETE")
    print("=" * 60)
    print(f"\n  Docs exported:   {fmt_num(writer_state['total'])}")
    print(f"  ES total:        {fmt_num(total_es)}")
    print(f"  Output file:     {OUTPUT_FILE}")
    print(f"  File size:       {fmt_size(OUTPUT_FILE)}")
    print(f"  Elapsed:         {elapsed:.1f}s  ({elapsed/60:.1f} min)")

    print(f"\n  Per-index breakdown:")
    for pattern, count in per_index_counts.items():
        print(f"    {pattern:30s} → {fmt_num(count):>12} docs")

    # Quick sanity-check on the written CSV
    print(f"\n── Quick sanity check ──")
    try:
        sample = pd.read_csv(OUTPUT_FILE, nrows=5)
        print(f"  Columns ({len(sample.columns)}): {list(sample.columns)}")
        print(f"  First 5 rows loaded OK")
    except Exception as e:
        print(f"  WARNING: could not read back CSV: {e}")

    print(f"\nDone. Load with: df = pd.read_csv('{OUTPUT_FILE}')")


if __name__ == "__main__":
    main()
