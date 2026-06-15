# Prediction API — IoT Honeypot Defensive AI
## PFE 2026 · Bouzira Mohamed & Bakhti Rayane · ESTIN

---

## Setup

```bash
pip install -r requirements_api.txt
python predict_api.py
```

Server starts on `http://localhost:5000`

---

## Model File Paths

The API expects this folder structure (relative to the script):

```
predict_api.py
../AI/Defensive/
    Xgboost_binary/
        xgboost_binary.pkl
    Xgboost_multi/
        xgboost_multiclass.pkl
        label_encoder.pkl          ← optional but recommended
    Autoencoder/
        autoencoder_anomaly.keras
        scaler_anomaly.pkl
    feature_list.pkl               ← optional but recommended
```

### Optional but highly recommended: save feature_list.pkl

If you have access to your training notebook, add this after fitting your models:

```python
import pickle
# Save the list of column names used for training
feature_cols = list(X_train.columns)   # or however you have them
with open("../AI/Defensive/feature_list.pkl", "wb") as f:
    pickle.dump(feature_cols, f)
```

Without it the API will try to reconstruct the feature vector from scratch,
which may not perfectly match the training column order.

---

## Endpoints

### `POST /predict`  ← main endpoint used by the website
Run all three models on a traffic sample.

**Request body:**
```json
{
    "protocol":           "MQTT",
    "dst_port":           1883,
    "bytes_sent":         1024,
    "bytes_received":     256,
    "request_rate":       5.0,
    "payload_size":       128,
    "session_duration":   30,
    "session_diversity":  2
}
```

**Optional additional fields:**
```json
{
    "src_port":               12345,
    "msg_rate_per_min":       5.0,
    "session_msg_count":      10,
    "session_req_count":      0,
    "session_topic_count":    2,
    "session_endpoint_count": 0,
    "session_path_count":     0,
    "mqtt_action":            "PUBLISH",
    "http_method":            "",
    "coap_method":            "",
    "log_type":               "mqtt"
}
```

**Response:**
```json
{
    "is_attack":          false,
    "attack_type":        "benign",
    "binary_confidence":  0.9821,
    "multi_confidence":   0.8741,
    "anomaly_score":      0.21,
    "overall_confidence": 0.9821,

    "binary": {
        "is_attack":    false,
        "attack_prob":  0.0179,
        "benign_prob":  0.9821,
        "confidence":   0.9821
    },
    "multi": {
        "attack_type":  "benign",
        "confidence":   0.8741,
        "top3": [
            {"class": "benign",        "prob": 0.8741},
            {"class": "reconnaissance","prob": 0.0612},
            {"class": "port_scan",     "prob": 0.0341}
        ]
    },
    "anomaly": {
        "is_anomaly":           false,
        "reconstruction_error": 0.0105,
        "threshold":            0.05,
        "anomaly_score":        0.21
    }
}
```

### `GET /health`
```json
{"status": "ok", "models": {"binary": true, "multi": true, "autoencoder": true, ...}}
```

### `GET /models/info`
Returns model paths, attack class labels, feature count.

### `POST /predict/binary`  — binary classifier only
### `POST /predict/multi`   — multiclass only
### `POST /predict/anomaly` — autoencoder only

---

## Point the Website at This API

In the Live Testing page, set the API URL to:
```
http://localhost:5000/predict
```

If deploying on a server, replace `localhost` with your server IP/domain.

---

## Tuning the Anomaly Threshold

The autoencoder uses a fixed threshold of `0.05` by default.
To calibrate it properly on your validation data:

```python
import pickle, numpy as np
from tensorflow import keras

# Load
with open("../AI/Defensive/Autoencoder/scaler_anomaly.pkl", "rb") as f:
    scaler = pickle.load(f)
ae = keras.models.load_model("../AI/Defensive/Autoencoder/autoencoder_anomaly.keras")

# Run on benign validation set
X_benign_scaled = scaler.transform(X_benign_val)
X_recon = ae.predict(X_benign_scaled)
errors = np.mean(np.square(X_benign_scaled - X_recon), axis=1)

# Set threshold at 95th percentile of benign errors
threshold = np.percentile(errors, 95)
print(f"Recommended threshold: {threshold:.6f}")
```

Then set `ANOMALY_FIXED_THRESHOLD = <value>` in predict_api.py.
