"""
predict_api.py  —  IoT Honeypot Defensive AI — Prediction API
PFE 2026 · Bouzira Mohamed & Bakhti Rayane Abderaouef · ESTIN

Usage:
    pip install flask xgboost scikit-learn keras tensorflow numpy pandas flask-cors
    python predict_api.py

Endpoints:
    POST /predict       — run all three models on a traffic sample
    POST /predict/binary   — binary classifier only
    POST /predict/multi    — multiclass classifier only
    POST /predict/anomaly  — autoencoder anomaly detector only
    GET  /health        — health check
    GET  /models/info   — loaded model metadata
"""

import os
import pickle
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Optional Keras import (autoencoder) ───────────────────────────────────────
try:
    from tensorflow import keras
    KERAS_AVAILABLE = True
except ImportError:
    try:
        import keras
        KERAS_AVAILABLE = True
    except ImportError:
        KERAS_AVAILABLE = False
        print("[WARN] Keras/TensorFlow not available — autoencoder disabled")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG — adjust paths to point at your model files
# ══════════════════════════════════════════════════════════════════════════════

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AI_DIR   = os.path.join(BASE_DIR, "..", "AI", "Defensive")

MODEL_PATHS = {
    "binary_model":     os.path.join(AI_DIR, "Xgboost_binary",    "xgboost_binary.pkl"),
    "multi_model":      os.path.join(AI_DIR, "Xgboost_multi",     "xgboost_multiclass.pkl"),
    "autoencoder":      os.path.join(AI_DIR, "Autoencoder",       "autoencoder_anomaly.keras"),
    "scaler_anomaly":   os.path.join(AI_DIR, "Autoencoder",       "scaler_anomaly.pkl"),
    # Optional — label encoder to decode multiclass integer → name
    "label_encoder":    os.path.join(AI_DIR, "Xgboost_multi",     "label_encoder.pkl"),
    # Binary + Multi share the same 36-feature list
    "feature_list":          os.path.join(AI_DIR, "Xgboost_binary", "feature_list.pkl"),
    # Autoencoder has 35 features (no payload_bytes_ratio)
    "feature_list_anomaly":  os.path.join(AI_DIR, "Autoencoder",    "feature_list.pkl"),
}

# Autoencoder anomaly threshold (percentile of reconstruction error on benign data)
# Tune this on your validation set; 95th-percentile is a common starting point
ANOMALY_THRESHOLD_PERCENTILE = 95
ANOMALY_FIXED_THRESHOLD      = None   # Set a float to override percentile, e.g. 0.032

# ══════════════════════════════════════════════════════════════════════════════
# FEATURE ENGINEERING
# Must exactly replicate what was done in the training notebooks.
# ══════════════════════════════════════════════════════════════════════════════

# Attack type labels in the same order as the LabelEncoder used during training.
# These are overwritten if label_encoder.pkl is found.
DEFAULT_ATTACK_LABELS = [
    "benign", "bruteforce", "coap_flood", "ddos",
    "exploit", "http_exploit", "mqtt_injection",
    "port_scan", "reconnaissance",
]

# All protocol values seen during training
PROTOCOL_VALUES = ["CoAP", "HTTP", "MQTT", "Network", "SSH"]

# Destination-port class bucketing (same as training feature engineering)
def port_class(port: int) -> int:
    """0 = well-known (≤1023), 1 = registered (1024–49151), 2 = dynamic (≥49152)"""
    if port <= 1023:
        return 0
    elif port <= 49151:
        return 1
    return 2


def build_feature_vector(data: dict, feature_columns: list) -> np.ndarray:
    """
    Convert raw API input → the same feature vector the models were trained on.

    Required input keys (all numeric unless noted):
        protocol           str   MQTT | HTTP | CoAP | SSH | Network
        dst_port           int
        bytes_sent         float
        bytes_received     float
        request_rate       float   requests/min
        payload_size       float   bytes
        session_duration   float   seconds
        session_diversity  int     topic_count + endpoint_count + path_count

    Optional (default 0 if absent):
        src_port           int
        msg_rate_per_min   float   (MQTT msg rate — use request_rate if not provided)
        session_msg_count  int
        session_req_count  int
        session_topic_count    int
        session_endpoint_count int
        session_path_count     int
        mqtt_action        str
        http_method        str
        coap_method        str
        coap_response_code str
        log_type           str
        eventid            str
    """

    # ── Raw numeric features ──────────────────────────────────────────────────
    bytes_sent    = float(data.get("bytes_sent",    0))
    bytes_recv    = float(data.get("bytes_received", 0))
    req_rate      = float(data.get("request_rate",  0))
    msg_rate      = float(data.get("msg_rate_per_min", req_rate))
    payload_size  = float(data.get("payload_size",  0))
    session_dur   = float(data.get("session_duration", 0))
    dst_port      = int(data.get("dst_port",        0))
    src_port      = int(data.get("src_port",        0))

    session_msg   = int(data.get("session_msg_count",      0))
    session_req   = int(data.get("session_req_count",      0))
    session_topic = int(data.get("session_topic_count",    0))
    session_endpt = int(data.get("session_endpoint_count", 0))
    session_path  = int(data.get("session_path_count",     0))

    # ── Engineered features (same as training notebooks) ─────────────────────
    total_bytes          = bytes_sent + bytes_recv
    bytes_ratio          = bytes_sent / (bytes_recv + 1)
    payload_bytes_ratio  = payload_size / (total_bytes + 1)
    src_port_class       = port_class(src_port)
    dst_port_class       = port_class(dst_port)
    session_diversity    = int(data.get("session_diversity",
                               session_topic + session_endpt + session_path))

    # Rate flags (90th-percentile threshold — use conservative defaults)
    # During inference we can't compute percentile on a single row;
    # approximate with reasonable thresholds matching training data ranges.
    MSG_RATE_90TH = 120.0   # ~90th percentile from training dataset
    REQ_RATE_90TH = 80.0
    msg_rate_high = 1 if msg_rate > MSG_RATE_90TH else 0
    req_rate_high = 1 if req_rate > REQ_RATE_90TH else 0

    mqtt_session_intensity = msg_rate * session_msg
    http_session_intensity = req_rate * session_req

    # ── Build base row ────────────────────────────────────────────────────────
    row = {
        # Raw
        "bytes_sent":             bytes_sent,
        "bytes_received":         bytes_recv,
        "payload_size":           payload_size,
        "dst_port":               dst_port,
        "src_port":               src_port,
        "request_rate":           req_rate,
        "msg_rate_per_min":       msg_rate,
        "session_duration":       session_dur,
        "session_msg_count":      session_msg,
        "session_req_count":      session_req,
        "session_topic_count":    session_topic,
        "session_endpoint_count": session_endpt,
        "session_path_count":     session_path,
        # Engineered
        "total_bytes":            total_bytes,
        "bytes_ratio":            bytes_ratio,
        "payload_bytes_ratio":    payload_bytes_ratio,
        "src_port_class":         src_port_class,
        "dst_port_class":         dst_port_class,
        "session_diversity":      session_diversity,
        "msg_rate_per_min_high":  msg_rate_high,
        "req_rate_per_min_high":  req_rate_high,
        "mqtt_session_intensity": mqtt_session_intensity,
        "http_session_intensity": http_session_intensity,
    }

    # ── One-hot encode protocol ────────────────────────────────────────────────
    protocol = str(data.get("protocol", "MQTT"))
    for pval in PROTOCOL_VALUES:
        row[f"protocol_{pval}"] = 1 if protocol == pval else 0

    # ── One-hot encode other categoricals (fill with 0 if not provided) ───────
    for cat_col, values in {
        "mqtt_action":         ["CONNECT","DISCONNECT","PINGREQ","PUBLISH","SUBSCRIBE","UNSUBSCRIBE"],
        "http_method":         ["DELETE","GET","HEAD","OPTIONS","POST","PUT"],
        "coap_method":         ["DELETE","GET","POST","PUT"],
        "coap_response_code":  ["2.01","2.02","2.03","2.04","2.05","4.00","4.04","5.00"],
        "log_type":            ["cowrie","coap","http","mqtt","network","platform"],
        "eventid":             [],  # too many — will be handled by feature_columns alignment
    }.items():
        raw_val = str(data.get(cat_col, ""))
        for v in values:
            row[f"{cat_col}_{v}"] = 1 if raw_val == v else 0

    # ── Align to exact training feature columns ───────────────────────────────
    if feature_columns:
        df = pd.DataFrame([row])
        # Add any missing columns as 0
        for col in feature_columns:
            if col not in df.columns:
                df[col] = 0
        # Keep only trained columns in the right order
        df = df[feature_columns]
        return df.values.astype(np.float32)
    else:
        # No feature list saved — return what we have as array
        vals = [float(v) for v in row.values()]
        return np.array(vals, dtype=np.float32).reshape(1, -1)


# ══════════════════════════════════════════════════════════════════════════════
# MODEL LOADER
# ══════════════════════════════════════════════════════════════════════════════

class ModelRegistry:
    def __init__(self):
        self.binary_model    = None
        self.multi_model     = None
        self.autoencoder     = None
        self.scaler_anomaly  = None
        self.label_encoder   = None
        self.feature_columns         = []   # 36 features — Binary + Multi
        self.feature_columns_anomaly = []   # 35 features — Autoencoder
        self.attack_labels   = DEFAULT_ATTACK_LABELS
        self._load_all()

    def _load_pkl(self, path: str, name: str):
        if not os.path.exists(path):
            print(f"[WARN] {name} not found at: {path}")
            return None
        try:
            with open(path, "rb") as f:
                obj = pickle.load(f)
            print(f"[OK]   Loaded {name}")
            return obj
        except Exception as e:
            print(f"[ERR]  Failed to load {name}: {e}")
            return None

    def _load_all(self):
        print("\n── Loading Models ──────────────────────────────")
        self.binary_model   = self._load_pkl(MODEL_PATHS["binary_model"],   "XGBoost Binary")
        self.multi_model    = self._load_pkl(MODEL_PATHS["multi_model"],    "XGBoost Multi")
        self.scaler_anomaly = self._load_pkl(MODEL_PATHS["scaler_anomaly"], "Scaler (Anomaly)")
        self.label_encoder  = self._load_pkl(MODEL_PATHS["label_encoder"],  "Label Encoder")

        # Feature column lists — separate for XGBoost vs Autoencoder
        fl = self._load_pkl(MODEL_PATHS["feature_list"], "Feature List (Binary/Multi)")
        if fl is not None:
            self.feature_columns = list(fl)
            print(f"       → {len(self.feature_columns)} features (Binary/Multi)")

        fl_ae = self._load_pkl(MODEL_PATHS["feature_list_anomaly"], "Feature List (Autoencoder)")
        if fl_ae is not None:
            self.feature_columns_anomaly = list(fl_ae)
            print(f"       → {len(self.feature_columns_anomaly)} features (Autoencoder)")

        # Label encoder → attack names
        if self.label_encoder is not None:
            try:
                self.attack_labels = list(self.label_encoder.classes_)
                print(f"       → Attack classes: {self.attack_labels}")
            except Exception:
                pass

        # Autoencoder (Keras)
        if KERAS_AVAILABLE:
            ae_path = MODEL_PATHS["autoencoder"]
            if os.path.exists(ae_path):
                try:
                    self.autoencoder = keras.models.load_model(ae_path)
                    print("[OK]   Loaded Autoencoder")
                except Exception as e:
                    print(f"[ERR]  Failed to load Autoencoder: {e}")
            else:
                print(f"[WARN] Autoencoder not found at: {ae_path}")

        print("────────────────────────────────────────────────\n")

    @property
    def status(self):
        return {
            "binary":              self.binary_model          is not None,
            "multi":               self.multi_model           is not None,
            "autoencoder":         self.autoencoder           is not None,
            "scaler":              self.scaler_anomaly        is not None,
            "label_enc":           self.label_encoder         is not None,
            "features_xgboost":    len(self.feature_columns),
            "features_autoencoder":len(self.feature_columns_anomaly),
        }


# ══════════════════════════════════════════════════════════════════════════════
# PREDICTION LOGIC
# ══════════════════════════════════════════════════════════════════════════════

def predict_binary(models: ModelRegistry, X: np.ndarray) -> dict:
    """XGBoost binary: is_attack + confidence."""
    if models.binary_model is None:
        return {"error": "Binary model not loaded"}
    try:
        # XGBoost can predict_proba (probability of class 1 = attack)
        if hasattr(models.binary_model, "predict_proba"):
            proba = models.binary_model.predict_proba(X)[0]
            attack_prob = float(proba[1])
            benign_prob = float(proba[0])
        else:
            raw = float(models.binary_model.predict(X)[0])
            attack_prob = raw
            benign_prob = 1.0 - raw

        is_attack = attack_prob >= 0.5
        return {
            "is_attack":        bool(is_attack),
            "attack_prob":      round(attack_prob, 4),
            "benign_prob":      round(benign_prob, 4),
            "confidence":       round(max(attack_prob, benign_prob), 4),
        }
    except Exception as e:
        return {"error": str(e)}


def predict_multi(models: ModelRegistry, X: np.ndarray) -> dict:
    """XGBoost multiclass: attack type + per-class probabilities."""
    if models.multi_model is None:
        return {"error": "Multi-class model not loaded"}
    try:
        if hasattr(models.multi_model, "predict_proba"):
            proba = models.multi_model.predict_proba(X)[0]
            pred_idx = int(np.argmax(proba))
            confidence = float(proba[pred_idx])

            # Top 3 classes
            top3_idx = np.argsort(proba)[::-1][:3]
            top3 = []
            for i in top3_idx:
                label = models.attack_labels[i] if i < len(models.attack_labels) else f"class_{i}"
                top3.append({"class": label, "prob": round(float(proba[i]), 4)})
        else:
            pred_idx  = int(models.multi_model.predict(X)[0])
            confidence = 1.0
            top3 = []

        attack_type = (models.attack_labels[pred_idx]
                       if pred_idx < len(models.attack_labels)
                       else f"class_{pred_idx}")

        return {
            "attack_type":  attack_type,
            "confidence":   round(confidence, 4),
            "top3":         top3,
        }
    except Exception as e:
        return {"error": str(e)}


def predict_anomaly(models: ModelRegistry, X: np.ndarray) -> dict:
    """Autoencoder: reconstruction error → anomaly score (uses 35-feature vector)."""
    if models.autoencoder is None:
        return {"error": "Autoencoder not loaded"}
    if models.scaler_anomaly is None:
        return {"error": "Anomaly scaler not loaded"}
    try:
        X_scaled = models.scaler_anomaly.transform(X)
        X_recon  = models.autoencoder.predict(X_scaled, verbose=0)
        recon_error = float(np.mean(np.square(X_scaled - X_recon)))

        # Determine threshold
        if ANOMALY_FIXED_THRESHOLD is not None:
            threshold = ANOMALY_FIXED_THRESHOLD
        else:
            # Without reference distribution, use a heuristic threshold
            # (In production: pre-compute this on validation benign data and save it)
            threshold = 0.05  # fallback — tune based on your validation set

        is_anomaly = recon_error > threshold

        return {
            "is_anomaly":      bool(is_anomaly),
            "reconstruction_error": round(recon_error, 6),
            "threshold":       round(threshold, 6),
            "anomaly_score":   round(min(recon_error / (threshold + 1e-9), 5.0), 4),
        }
    except Exception as e:
        return {"error": str(e)}


def predict_all(models: ModelRegistry, data: dict) -> dict:
    """Run all three models and combine results."""
    # XGBoost models use 36 features
    X = build_feature_vector(data, models.feature_columns)
    # Autoencoder uses 35 features (no payload_bytes_ratio)
    X_ae = build_feature_vector(data, models.feature_columns_anomaly)

    binary  = predict_binary(models,  X)
    multi   = predict_multi(models,   X)
    anomaly = predict_anomaly(models, X_ae)

    # ── Combined verdict ──────────────────────────────────────────────────────
    # Attack if binary says attack OR autoencoder flags anomaly
    bin_attack  = binary.get("is_attack",  False)
    ae_anomaly  = anomaly.get("is_anomaly", False)
    is_attack   = bin_attack or ae_anomaly

    # Attack type comes from multi-class (only meaningful if attack detected)
    attack_type = multi.get("attack_type", "unknown") if is_attack else "benign"

    # Overall confidence = max of available model confidences
    confidences = []
    if "confidence" in binary:
        confidences.append(binary["confidence"])
    if "confidence" in multi and is_attack:
        confidences.append(multi["confidence"])
    overall_conf = round(max(confidences), 4) if confidences else 0.0

    return {
        # Top-level summary (what the website reads)
        "is_attack":          bool(is_attack),
        "attack_type":        attack_type,
        "binary_confidence":  binary.get("confidence",   None),
        "multi_confidence":   multi.get("confidence",    None),
        "anomaly_score":      anomaly.get("anomaly_score", None),
        "overall_confidence": overall_conf,

        # Per-model detail
        "binary":   binary,
        "multi":    multi,
        "anomaly":  anomaly,
    }


# ══════════════════════════════════════════════════════════════════════════════
# FLASK APP
# ══════════════════════════════════════════════════════════════════════════════

app    = Flask(__name__)
CORS(app)   # Allow cross-origin requests from the HTML site
models = ModelRegistry()


def _get_json() -> tuple:
    """Parse request JSON, return (data, error_response)."""
    data = request.get_json(silent=True)
    if not data:
        return None, (jsonify({"error": "Request body must be JSON"}), 400)
    return data, None


# ── /health ───────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "models": models.status
    })


# ── /models/info ──────────────────────────────────────────────────────────────

@app.route("/models/info", methods=["GET"])
def models_info():
    return jsonify({
        "binary_model":    MODEL_PATHS["binary_model"],
        "multi_model":     MODEL_PATHS["multi_model"],
        "autoencoder":     MODEL_PATHS["autoencoder"],
        "attack_labels":   models.attack_labels,
        "n_features":      len(models.feature_columns),
        "feature_columns": models.feature_columns[:20],  # first 20 for reference
        "models_loaded":   models.status,
    })


# ── /predict  (main endpoint — all three models) ──────────────────────────────

@app.route("/predict", methods=["POST"])
def predict():
    """
    Body (JSON):
    {
        "protocol":          "MQTT",
        "dst_port":          1883,
        "bytes_sent":        1024,
        "bytes_received":    256,
        "request_rate":      5.0,
        "payload_size":      128,
        "session_duration":  30,
        "session_diversity": 2
    }
    """
    data, err = _get_json()
    if err:
        return err

    result = predict_all(models, data)
    return jsonify(result)


# ── /predict/binary ───────────────────────────────────────────────────────────

@app.route("/predict/binary", methods=["POST"])
def predict_binary_route():
    data, err = _get_json()
    if err:
        return err
    X = build_feature_vector(data, models.feature_columns)
    return jsonify(predict_binary(models, X))


# ── /predict/multi ────────────────────────────────────────────────────────────

@app.route("/predict/multi", methods=["POST"])
def predict_multi_route():
    data, err = _get_json()
    if err:
        return err
    X = build_feature_vector(data, models.feature_columns)
    return jsonify(predict_multi(models, X))


# ── /predict/anomaly ──────────────────────────────────────────────────────────

@app.route("/predict/anomaly", methods=["POST"])
def predict_anomaly_route():
    data, err = _get_json()
    if err:
        return err
    X = build_feature_vector(data, models.feature_columns_anomaly)
    return jsonify(predict_anomaly(models, X))


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  IoT Honeypot — Defensive AI Prediction API")
    print("  PFE 2026 · ESTIN")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    app.run(host="0.0.0.0", port=5000, debug=False)
