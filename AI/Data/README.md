# Data Science Report — IoT Honeypot AI Pipeline
## PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef

---

## 1. Dataset Description

| Property | Value |
|----------|-------|
| **Source** | Real attacker traffic from a cloud-deployed IoT smart-home honeypot (Google Cloud) |
| **Collection period** | April 2026 |
| **Raw size** | 2,682,396 rows × 47 columns (648 MB) |
| **Balanced size** | 244,085 rows × 46 columns (87.9 MB) |
| **Protocols covered** | MQTT, HTTP, CoAP, SSH/Telnet (Cowrie), Network (tshark), IoT Platform |
| **Elasticsearch indices** | 6 indices (honeypot-mqtt-*, honeypot-http-*, honeypot-coap-*, honeypot-cowrie-*, honeypot-network-*, honeypot-platform-*) |
| **Export method** | Elasticsearch Scroll API → chunked CSV with proper quoting |

### Data Collection Pipeline
```
Honeypot services → JSON log files → Filebeat → Logstash → Elasticsearch → export_data.py → CSV
```

---

## 2. Data Quality Issues Found

### 2.1 Severe Class Imbalance
- **Problem:** 98.7% benign vs 1.3% attack in raw data (2.65M benign, 34K attack)
- **Impact:** Models would achieve 98.7% accuracy by predicting all-benign, learning nothing about attacks
- **Severity:** Critical — makes standard training useless

### 2.2 Missing Values (Protocol-Specific NaN)
- **Problem:** Each log type only populates its own fields. MQTT logs have `mqtt_action`, `topic`, `qos` etc., but HTTP/CoAP/Cowrie fields are NaN for those rows (and vice versa).
- **Pattern:** Up to 80%+ NaN in protocol-specific columns — this is **expected and by design**, not data corruption
- **Example:** `command` column is 100% NaN (Cowrie field, but no command data was captured)

### 2.3 Inconsistent Boolean Types
- **Problem:** Boolean columns (`is_attack`, `is_known_topic`, `retain`, `login_success`, etc.) stored as strings (`"True"`, `"False"`, `"true"`, `"false"`) or mixed types across indices
- **Cause:** Different Elasticsearch index mappings + JSON serialization inconsistencies

### 2.4 Type Inconsistencies in Numeric Columns
- **Problem:** Numeric columns like `src_port`, `dst_port`, `payload_size` sometimes stored as strings in ES
- **Cause:** Dynamic mapping in Elasticsearch auto-detected types differently across indices

### 2.5 CSV Parsing Errors
- **Problem:** Initial CSV export produced malformed rows — "Expected 48 fields, saw 52"
- **Cause:** HTTP user-agent strings containing commas (e.g., "Nmap Scripting Engine") were not properly quoted, and some ES indices returned extra fields beyond the expected schema
- **Fix:** Added `csv.QUOTE_NONNUMERIC` and strict column filtering in `export_data.py`

### 2.6 Extremely Rare Attack Classes
- **Problem:** Some attack types had very few samples: `malware_download` (1 sample), `post_exploit` (20 samples)
- **Impact:** Too few samples for SMOTE (needs k_neighbors + 1 minimum)

### 2.7 Duplicate Rows
- **Problem:** Exact duplicate rows present in raw export
- **Cause:** Filebeat re-delivery after log rotation, possible ES duplicate indexing

---

## 3. Solutions Applied

### 3.1 Class Imbalance → Downsample + SMOTE

**Strategy:** Two-phase rebalancing in `clean_and_balance.py`:

1. **Downsample benign:** 2.65M → 75,600 (25,000 per major protocol: mqtt, http, coap; 200 each for cowrie, network, platform to maintain representation)
2. **SMOTE minority classes:** Upsample each attack type to 12,000 samples using Synthetic Minority Oversampling Technique

**Why SMOTE over random oversampling:**
- Random oversampling creates exact copies → overfitting
- SMOTE generates synthetic samples by interpolating between nearest neighbors → better generalization
- Used `k_neighbors=3` (limited by smallest class size after merging)

**Result:**
| Class | Before | After |
|-------|--------|-------|
| benign | 2,650,000+ | 75,600 |
| Each attack type | 30–15,000 | 12,000 |
| **Total** | **2,682,396** | **244,085** |

### 3.2 Missing Values → Context-Aware Fill with 0

**Rationale:** Protocol-specific NaN values are not "missing data" — they represent "not applicable." An MQTT log has no `http_method` because it's not HTTP. Filling with 0 is semantically correct: zero HTTP status code means "no HTTP interaction."

**Applied in:** Notebooks (not in `clean_and_balance.py`, which only handles type fixes)

### 3.3 Boolean Type Fixes

**Solution:** Map all boolean variants to consistent `True`/`False`:
```python
{"True": True, "False": False, "true": True, "false": False,
 1: True, 0: False, "1": True, "0": False}
```

**Applied in:** Both `clean_and_balance.py` (for SMOTE compatibility) and notebooks (for ML features)

### 3.4 Numeric Type Coercion

**Solution:** `pd.to_numeric(col, errors="coerce")` — invalid values become NaN, then filled with 0

### 3.5 Rare Class Merging

**Solution:** Merged extremely rare attack types into parent categories:
- `malware_download` (1 sample) → `exploit`
- `post_exploit` (20 samples) → `exploit`

**Rationale:** SMOTE requires at least `k_neighbors + 1` samples per class. After merging, all classes have ≥30 real samples.

### 3.6 CSV Export Fix

**Solution:** Two fixes in `export_data.py`:
1. Added `quoting=csv.QUOTE_NONNUMERIC` to handle commas in string fields
2. Changed to strict column filtering: `df = df[[c for c in COLUMN_ORDER if c in df.columns]]` to prevent extra ES fields from creating inconsistent column counts

---

## 4. Feature Engineering

All feature engineering is performed **in the notebooks**, not in the preprocessing script, to maintain reproducibility and visibility.

### Features Created

| Feature | Formula | Rationale |
|---------|---------|-----------|
| `bytes_ratio` | `bytes_sent / (bytes_received + 1)` | Attackers tend to send much more than they receive (reconnaissance, flooding) |
| `total_bytes` | `bytes_sent + bytes_received` | Overall traffic volume — DDoS and scans generate high total bytes |
| `src_port_class` | 0 (well-known), 1 (registered), 2 (dynamic) | Well-known source ports are unusual (potential spoofing) |
| `dst_port_class` | Same classification for destination port | Attacks often target well-known service ports |
| `msg_rate_per_min_high` | 1 if rate > 90th percentile | Flag for abnormally fast MQTT messaging |
| `req_rate_per_min_high` | 1 if rate > 90th percentile | Flag for abnormally fast HTTP requests |
| `mqtt_session_intensity` | `msg_rate_per_min × session_msg_count` | Captures both speed and volume of MQTT abuse |
| `http_session_intensity` | `req_rate_per_min × session_req_count` | Captures both speed and volume of HTTP abuse |
| `payload_bytes_ratio` | `payload_size / (total_bytes + 1)` | Ratio of payload to total — malformed packets may have unusual ratios |
| `session_diversity` | Sum of `session_topic_count + session_endpoint_count + session_path_count` | Attackers scanning tend to visit many different resources |

---

## 5. Encoding Strategy

### One-Hot Encoding (used for all models)
**Columns encoded:** `log_type`, `protocol`, `mqtt_action`, `http_method`, `coap_method`, `coap_response_code`, `eventid`

**Why one-hot over label encoding for features:**
- These are nominal categorical variables with no inherent order
- Label encoding would imply `mqtt=0 < http=1 < coap=2`, which is meaningless
- Tree models (XGBoost) can handle one-hot efficiently

### Label Encoding (multiclass target only)
**Column:** `attack_type` → integer labels (0–14)

**Why label encoding for target:**
- XGBoost's `multi:softprob` requires integer-encoded targets
- Saved `LabelEncoder` object for decoding predictions back to class names

---

## 6. Feature Selection

### Two-Stage Selection Pipeline

**Stage 1 — Variance Threshold (threshold=0.01):**
- Removes features with near-zero variance (almost constant across all samples)
- These features carry no discriminative information

**Stage 2 — Correlation-Based Removal (>0.95):**
- Removes one feature from each pair with Pearson correlation >0.95
- Highly correlated features are redundant — keeping both increases dimensionality without adding information
- Reduces overfitting risk and training time

---

## 7. Model Selection Rationale

### Model 1: XGBoost Binary Classifier
**Why XGBoost:**
- Handles mixed feature types (numeric + one-hot) natively
- Built-in handling of missing values
- `scale_pos_weight` parameter directly addresses class imbalance
- Gradient boosting is state-of-the-art for tabular data
- Fast training, interpretable feature importances

### Model 2: XGBoost Multiclass Classifier
**Why same algorithm:**
- Same advantages as binary, extended to 15 classes via `multi:softprob`
- Provides per-class probability outputs for ROC analysis
- Consistent pipeline with binary model for comparison

### Model 3: Autoencoder (Anomaly Detection)
**Why autoencoder over other anomaly detection methods:**
- **vs. Isolation Forest:** Autoencoder learns a richer representation of "normal" — captures non-linear patterns in multi-protocol IoT data
- **vs. One-Class SVM:** Scales better to 244K samples and 50+ features
- **Key advantage:** Trained on benign-only data — detects **novel** attack types never seen in training
- **Architecture choice:** BatchNorm + Dropout prevent overfitting to training benign patterns, EarlyStopping prevents over-reconstruction

---

## 8. Evaluation Metrics Chosen

### Why Not Just Accuracy?
With balanced data (after SMOTE), accuracy is more meaningful than in the raw dataset. However, for security applications:

| Metric | Why It Matters |
|--------|---------------|
| **Precision** | High precision = few false alarms. Important for operational honeypot monitoring — too many false alerts cause alert fatigue |
| **Recall** | High recall = few missed attacks. Critical for security — a missed attack could mean undetected breach |
| **F1 Score** | Harmonic mean of precision and recall — balances both concerns |
| **ROC AUC** | Measures discrimination ability across all thresholds — robust to class distribution |
| **Average Precision (PR AUC)** | Better than ROC AUC for imbalanced data — focuses on positive class performance |

### Per-Model Metrics

**Binary Classification:** F1, Precision, Recall, ROC AUC, PR AUC, 5-fold CV
**Multiclass:** F1-macro, Per-class ROC AUC, Per-class precision/recall, Error analysis (misclassification patterns)
**Autoencoder:** ROC AUC on reconstruction error, Threshold sweep (precision/recall vs percentile), Per-attack-type detection rate

---

## 9. Results Summary

| Model | Accuracy | Key Metric | Score | Notes |
|-------|----------|-----------|-------|-------|
| XGBoost Binary | **99%** | ROC AUC / F1 | ~0.99 | Tuned with RandomizedSearchCV, 5-fold CV |
| XGBoost Multiclass | **94%** | Macro F1 | ~0.94 | 15 classes via `multi:softprob` |
| Autoencoder | **96%** | ROC AUC | ~0.96 | Trained on benign-only, threshold sweep |

*Results obtained after fixing data leakage (`is_internal`, `is_known_device`, `"synthetic"` artifacts).*

---

## 10. Limitations & Future Work

### Current Limitations

1. **Synthetic data from SMOTE:** ~70% of attack samples are synthetic. While SMOTE preserves statistical properties, synthetic samples lack the real-world noise and diversity of actual attacks. Models may learn SMOTE artifacts rather than true attack patterns.

2. **Protocol-specific feature sparsity:** Each row has ~60-80% of features as 0 (not applicable for that protocol). This creates a very sparse feature space that may not generalize well across protocols.

3. **Limited attack diversity:** 15 attack types from a single honeypot deployment. Real-world IoT networks face a much wider range of attacks (e.g., firmware exploits, zero-days, lateral movement).

4. **Single honeypot instance:** All data comes from one deployment on Google Cloud. Attacker behavior may differ based on geographic location, IP reputation, time of year, etc.

5. **No temporal features:** The current pipeline drops timestamps. Time-based features (hour of day, day of week, inter-arrival times) could improve detection since many attacks follow temporal patterns.

### Future Work

1. **Longer collection period:** Continue honeypot operation for 3-6 months to collect more diverse real attack data, reducing dependence on SMOTE
2. **Temporal features:** Extract hour_of_day, day_of_week, is_night from timestamps for temporal attack pattern detection
3. **Sequence modeling:** Use LSTM/Transformer on session-level sequences instead of individual log entries
4. **Offensive RL model:** Train a reinforcement learning agent to simulate attacks against the honeypot, generating adversarial examples for defensive model hardening
5. **Ensemble approach:** Combine XGBoost (supervised) + Autoencoder (unsupervised) predictions for more robust detection
6. **Real-time deployment:** Integrate trained models into the ELK pipeline via a Logstash filter or sidecar container for live attack detection

---

## 11. Null‑Byte and Missing‑Value Handling

- **Problem:** Certain columns contain the literal string `"null"` or the placeholder `"synthetic"` (introduced by SMOTE). These strings were interpreted as categorical values during one‑hot encoding, creating artifact columns (e.g., `mqtt_action_synthetic`) that existed only for attack rows — a direct form of **data leakage**. Additionally, passing these strings to `VarianceThreshold` raised `ValueError: could not convert string to float`.
- **Solution:** Immediately after loading the CSV, replace both markers with `np.nan`:
  ```python
  data.replace("synthetic", np.nan, inplace=True)
  ```
  Then apply `fillna(0)` for numeric columns. This ensures numeric pipelines (VarianceThreshold, MinMaxScaler, correlation matrix) receive only valid numbers, and no artificial one‑hot columns are created.

---

## 12. Duplicate Row Detection and Removal

- **Problem:** The raw Elasticsearch export contained exact duplicate log entries (identical across all 47 columns). Root causes include Filebeat re‑delivery after log rotation and possible duplicate indexing in Elasticsearch.
- **Impact:** Duplicates inflate the majority class further, bias cross‑validation folds (same sample can appear in both train and test), and waste SMOTE computation on redundant points.
- **Solution:** Remove exact duplicates before any balancing:
  ```python
  data.drop_duplicates(inplace=True)
  ```
  Applied in `clean_and_balance.py` before the downsample + SMOTE pipeline. Row count dropped from 2,682,396 to ~2,680,000 unique rows.

---

## 13. Outlier Identification and Treatment

- **Problem:** Numeric fields such as `payload_size`, `bytes_sent`, `bytes_received`, and `msg_rate_per_min` exhibit extreme right‑skewed distributions. A small number of rows show values several orders of magnitude above the median (e.g., `bytes_sent` > 1 GB from a single log entry), caused by malformed packets, logging errors, or actual large‑payload attacks (DDoS floods).
- **Impact:** Extreme outliers dominate variance‑based feature selection (VarianceThreshold) and distort MinMaxScaler ranges, compressing the majority of values into a tiny band near 0.
- **Solution:** Cap outliers at the 99th percentile per column using `np.clip`:
  ```python
  for col in numeric_cols:
      p99 = data[col].quantile(0.99)
      data[col] = data[col].clip(upper=p99)
  ```
  This preserves the overall distribution shape while preventing a handful of extreme values from distorting the feature space. Applied in notebooks before feature engineering.

---

## 14. Normalization vs. Standardization

### When and Why Each Was Used

| Technique | Formula | Used In | Rationale |
|-----------|---------|---------|-----------|
| **Min‑Max Normalization** | `(x - min) / (max - min)` → `[0, 1]` | Autoencoder | Sigmoid output layer expects inputs in `[0, 1]`; `MinMaxScaler` fitted on benign‑only training data |
| **Z‑score Standardization** | `(x - μ) / σ` → mean=0, std=1 | XGBoost (optional) | Centers features for hyper‑parameter search convergence; not strictly required for tree models |

- **Key decision:** The `MinMaxScaler` for the autoencoder is fitted **only on benign training data**. This is critical — if attack data influenced the scaler, normal‑range features in test attacks would appear "normal" after scaling, reducing detection power.
- **Tree models (XGBoost):** Gradient‑boosted trees are invariant to monotonic feature transformations, so standardization is optional. We applied it during `RandomizedSearchCV` to stabilize convergence of the learning‑rate search.

---

## 15. Data Leakage — Identification and Prevention

- **Problem 1 — Perfect proxy columns:** `is_internal` and `is_known_device` are deterministic functions of the target variable. In our honeypot, **all** benign traffic is internal + known‑device, and **all** attack traffic is external + unknown. Including these features gives the model a trivial shortcut → 100% accuracy with zero generalization.
- **Problem 2 — SMOTE string artifacts:** `clean_and_balance.py` fills categorical columns with the string `"synthetic"` for SMOTE‑generated rows. After one‑hot encoding, columns like `mqtt_action_synthetic` appear only in attack rows — another perfect predictor.
- **Solution:** Drop both leaky columns and neutralize the `"synthetic"` marker:
  ```python
  drop_cols = [..., 'is_internal', 'is_known_device']
  data.drop(columns=[c for c in drop_cols if c in data.columns], inplace=True)
  data.replace("synthetic", np.nan, inplace=True)
  ```
  After this fix, binary classification accuracy dropped from 100% to a realistic **99%**, confirming the model now learns genuine traffic patterns.

---

## 16. Feature Engineering — Complete Reference

All feature engineering is performed **in the notebooks** (not in `clean_and_balance.py`) to maintain full visibility and reproducibility.

| Feature | Formula | Rationale |
|---------|---------|-----------|
| `bytes_ratio` | `bytes_sent / (bytes_received + 1)` | Attackers tend to send much more than they receive (recon, flooding) |
| `total_bytes` | `bytes_sent + bytes_received` | Overall traffic volume — DDoS and scans generate high totals |
| `src_port_class` | 0=well‑known (≤1023), 1=registered (≤49151), 2=dynamic | Well‑known source ports are unusual (potential spoofing) |
| `dst_port_class` | Same bucketing for destination port | Attacks often target well‑known service ports |
| `msg_rate_per_min_high` | 1 if rate > 90th percentile of non‑zero values | Binary flag for abnormally fast MQTT messaging |
| `req_rate_per_min_high` | 1 if rate > 90th percentile of non‑zero values | Binary flag for abnormally fast HTTP requests |
| `mqtt_session_intensity` | `msg_rate_per_min × session_msg_count` | Captures both speed and volume of MQTT abuse |
| `http_session_intensity` | `req_rate_per_min × session_req_count` | Captures both speed and volume of HTTP abuse |
| `payload_bytes_ratio` | `payload_size / (total_bytes + 1)` | Malformed packets may have unusual payload‑to‑total ratios |
| `session_diversity` | `session_topic_count + session_endpoint_count + session_path_count` | Scanning attackers visit many different resources |

### Feature Selection Pipeline
1. **Variance Threshold (0.01):** Drops near‑constant columns (carry no discriminative information)
2. **Pearson Correlation Pruning (>0.95):** Removes one feature from each highly correlated pair, reducing dimensionality by ~30% without losing information

---

## 17. Encoding Strategy

| Column Type | Encoding | Reason |
|-------------|----------|--------|
| Nominal categoricals (`log_type`, `protocol`, `mqtt_action`, `http_method`, `coap_method`, `coap_response_code`, `eventid`) | **One‑Hot** | No inherent order — label encoding would imply `mqtt < http < coap` |
| Binary target (`is_attack`) | **Boolean → int** (0/1) | Required by all classifiers |
| Multiclass target (`attack_type`) | **LabelEncoder** → integer (0–14) | XGBoost `multi:softprob` requires integer targets; encoder saved for decoding |
| Boolean flags (`retain`, `is_known_topic`, `login_success`, etc.) | **Map to float** (0.0/1.0) | Original data mixed `"True"/"False"/True/False/"true"/"false"` — unified to numeric |

---

## 18. End‑to‑End Pipeline Summary

```
1.  Load CSV (244,085 × 46)
2.  Replace "synthetic" / "null" markers → np.nan
3.  Drop identifier columns (IPs, timestamps, client_id, topic, etc.)
4.  Drop leakage columns (is_internal, is_known_device)
5.  Remove exact duplicate rows
6.  Boolean unification → float 0.0 / 1.0
7.  Numeric type coercion (pd.to_numeric, errors='coerce')
8.  Outlier clipping at 99th percentile
9.  Fill remaining NaN → 0
10. Feature engineering (10 new features)
11. One‑hot encode categoricals
12. Variance threshold (drop near‑zero variance)
13. Correlation pruning (drop r > 0.95)
14. Train/test split (80/20, stratified)
15. Normalization (MinMax for autoencoder) / Standardization (Z‑score for XGBoost)
16. Model training + RandomizedSearchCV
17. 5‑fold stratified cross‑validation
18. Evaluation (confusion matrix, ROC, PR curve, feature importance)
19. Save models + metadata
```

---

## 19. Updated Results Summary

| Model | Accuracy | Key Metric | Score |
|-------|----------|-----------|-------|
| XGBoost Binary | **99%** | F1 / ROC AUC | ~0.99 |
| XGBoost Multiclass | **94%** | Macro F1 | ~0.94 |
| Autoencoder Anomaly | **96%** | ROC AUC | ~0.96 |

These results were obtained **after** fixing data leakage (removing `is_internal`, `is_known_device`, and `"synthetic"` artifacts). The scores reflect genuine model learning on real traffic patterns rather than shortcut features.

---

*Report generated as part of PFE 2025 — AI‑Driven IoT Smart‑Home Honeypot*
*Last updated: April 2026*
