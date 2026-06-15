# ================================================================
#  HTTP SERVER — Flask
#  Receives data from sim-camera and sim-doorbell
#  Exposes status and command endpoints for IoT platform
#  v2 - optimized log structure, same business logic
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

from flask import Flask, request, jsonify
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict

app = Flask(__name__)

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
HONEYPOT_IP = os.environ.get('HONEYPOT_IP', '172.20.0.2')
LISTEN_PORT = int(os.environ.get('HTTP_PORT', 8080))

KNOWN_DEVICES = {
    '172.20.0.10',  # camera
    '172.20.0.16',  # doorbell
    '172.20.0.2',   # main-server (IoT platform)
    '127.0.0.1',
}

KNOWN_ENDPOINTS = {
    '/api/camera', '/api/camera/status', '/api/camera/command', '/api/camera/poll',
    '/api/doorbell', '/api/doorbell/status', '/api/doorbell/command', '/api/doorbell/poll'
}

# ----------------------------------------------------------------
# LOGGING SETUP
# ----------------------------------------------------------------
os.makedirs('/var/log/http', exist_ok=True)
logger = logging.getLogger('http_server')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/http/http.json')
fh.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(fh)

# ── SESSION TRACKING ─────────────────────────────────────────────
sessions    = {}
rate_window = defaultdict(list)

def _get_or_create_session(src_ip):
    if src_ip not in sessions:
        sessions[src_ip] = {
            'session_id':   str(uuid.uuid4()),
            'connect_time': time.time(),
            'req_count':    0,
            'endpoints':    set(),
        }
    return sessions[src_ip]

def _req_rate(src_ip):
    now = time.time()
    rate_window[src_ip] = [t for t in rate_window[src_ip] if now - t < 60]
    rate_window[src_ip].append(now)
    return len(rate_window[src_ip])

def _heuristic_label(src_ip, endpoint, req_rate, body_size):
    is_known = src_ip in KNOWN_DEVICES
    is_known_ep = endpoint in KNOWN_ENDPOINTS
    if not is_known:
        if not is_known_ep:
            return True, 'endpoint_scan'
        if req_rate > 50:
            return True, 'ddos'
        if any(x in endpoint for x in ['..', '/etc/', '/admin', '/passwd', '/config']):
            return True, 'path_traversal'
        if body_size > 50000:
            return True, 'large_payload'
        return True, 'unknown'
    return False, 'benign'

def log_event(endpoint, status_code, extra=None):
    src_ip    = request.remote_addr
    method    = request.method
    body      = request.get_data()
    body_size = len(body)
    sess      = _get_or_create_session(src_ip)
    req_rate  = _req_rate(src_ip)

    sess['req_count'] += 1
    sess['endpoints'].add(endpoint)

    is_known_device = src_ip in KNOWN_DEVICES
    is_attack, attack_type = _heuristic_label(src_ip, endpoint, req_rate, body_size)

    # Store body only for suspicious requests
    store_body = not is_known_device or is_attack
    body_field = body[:512].decode('utf-8', errors='replace') if store_body and body_size > 0 else None

    entry = {
        # ── Common fields ──
        "@timestamp":             datetime.now(timezone.utc).isoformat(),
        "log_type":               "http",
        "src_ip":                 src_ip,
        "dst_ip":                 HONEYPOT_IP,
        "src_port":               request.environ.get('REMOTE_PORT', 0),
        "dst_port":               LISTEN_PORT,
        "protocol":               "HTTP",
        "bytes_sent":             body_size,
        "bytes_received":         0,
        "is_internal":            src_ip.startswith('172.20.') or src_ip == '127.0.0.1',
        "is_known_device":        is_known_device,
        "is_attack":              is_attack,
        "attack_type":            attack_type,
        "session_id":             sess['session_id'],

        # ── HTTP-specific fields ──
        "http_method":            method,
        "http_endpoint":          endpoint,
        "http_status_code":       status_code,
        "http_version":           request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1'),
        "user_agent":             request.headers.get('User-Agent', ''),
        "content_type":           request.headers.get('Content-Type', ''),
        "body_size":              body_size,
        "body":                   body_field,

        # ── Behavioral features ──
        "session_req_count":      sess['req_count'],
        "session_endpoint_count": len(sess['endpoints']),
        "req_rate_per_min":       req_rate,
        "session_duration_s":     round(time.time() - sess['connect_time'], 2),
    }
    if extra:
        entry.update(extra)

    logger.info(json.dumps(entry))
    print(f"[HTTP] {method} {endpoint} from {src_ip} → {status_code}", flush=True)

# ----------------------------------------------------------------
# IN-MEMORY STATE STORE
# ----------------------------------------------------------------
device_state = {
    "camera": {
        "event_type": "none",
        "night_mode": False,
        "last_seen":  "--",
        "updated_at": None
    },
    "doorbell": {
        "event_type":    "none",
        "battery_level": "--",
        "wifi_signal":   "--",
        "last_seen":     "--",
        "updated_at":    None
    }
}

pending_commands = {
    "camera":   None,
    "doorbell": None
}

# ----------------------------------------------------------------
# CAMERA — receive data from sim-camera
# ----------------------------------------------------------------
@app.route('/api/camera', methods=['POST'])
def camera_receive():
    data   = request.get_json(silent=True) or {}
    src_ip = request.remote_addr

    device_state["camera"]["event_type"] = data.get("event_type", "none")
    device_state["camera"]["night_mode"] = data.get("night_mode", False)
    device_state["camera"]["last_seen"]  = datetime.now(timezone.utc).strftime('%H:%M:%S')
    device_state["camera"]["updated_at"] = datetime.now(timezone.utc).isoformat()

    log_event('/api/camera', 200, extra={
        "device":     "camera",
        "event_type": data.get("event_type"),
        "night_mode": data.get("night_mode"),
        "rtsp_url":   data.get("rtsp_url"),
    })
    return jsonify({"status": "ok", "device": "camera"}), 200

# ----------------------------------------------------------------
# CAMERA — return last known state to IoT platform
# ----------------------------------------------------------------
@app.route('/api/camera/status', methods=['GET'])
def camera_status():
    return jsonify(device_state["camera"]), 200

# ----------------------------------------------------------------
# CAMERA — receive command from IoT platform
# ----------------------------------------------------------------
@app.route('/api/camera/command', methods=['POST'])
def camera_command():
    data    = request.get_json(silent=True) or {}
    command = data.get("command")
    pending_commands["camera"] = command
    log_event('/api/camera/command', 200, extra={
        "device": "camera", "command": command
    })
    return jsonify({"status": "ok", "command": command}), 200

# ----------------------------------------------------------------
# CAMERA — simulator polls this to get pending command
# ----------------------------------------------------------------
@app.route('/api/camera/poll', methods=['GET'])
def camera_poll():
    cmd = pending_commands["camera"]
    pending_commands["camera"] = None
    return jsonify({"command": cmd}), 200

# ----------------------------------------------------------------
# DOORBELL — receive data from sim-doorbell
# ----------------------------------------------------------------
@app.route('/api/doorbell', methods=['POST'])
def doorbell_receive():
    data   = request.get_json(silent=True) or {}
    src_ip = request.remote_addr

    device_state["doorbell"]["event_type"]    = data.get("event_type", "none")
    device_state["doorbell"]["battery_level"] = data.get("battery_level", "--")
    device_state["doorbell"]["wifi_signal"]   = data.get("wifi_signal", "--")
    device_state["doorbell"]["last_seen"]     = datetime.now(timezone.utc).strftime('%H:%M:%S')
    device_state["doorbell"]["updated_at"]    = datetime.now(timezone.utc).isoformat()

    log_event('/api/doorbell', 200, extra={
        "device":        "doorbell",
        "event_type":    data.get("event_type"),
        "battery_level": data.get("battery_level"),
        "wifi_signal":   data.get("wifi_signal"),
    })
    return jsonify({"status": "ok", "device": "doorbell"}), 200

# ----------------------------------------------------------------
# DOORBELL — return last known state to IoT platform
# ----------------------------------------------------------------
@app.route('/api/doorbell/status', methods=['GET'])
def doorbell_status():
    return jsonify(device_state["doorbell"]), 200

# ----------------------------------------------------------------
# DOORBELL — receive command from IoT platform
# ----------------------------------------------------------------
@app.route('/api/doorbell/command', methods=['POST'])
def doorbell_command():
    data    = request.get_json(silent=True) or {}
    command = data.get("command")
    pending_commands["doorbell"] = command
    log_event('/api/doorbell/command', 200, extra={
        "device": "doorbell", "command": command
    })
    return jsonify({"status": "ok", "command": command}), 200

# ----------------------------------------------------------------
# DOORBELL — simulator polls this to get pending command
# ----------------------------------------------------------------
@app.route('/api/doorbell/poll', methods=['GET'])
def doorbell_poll():
    cmd = pending_commands["doorbell"]
    pending_commands["doorbell"] = None
    return jsonify({"command": cmd}), 200

# ----------------------------------------------------------------
# CATCH-ALL — log attacker probing unknown endpoints
# ----------------------------------------------------------------
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>',            methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def catch_all(path):
    endpoint = f'/{path}'
    log_event(endpoint, 200)
    return jsonify({"status": "ok"}), 200

# ----------------------------------------------------------------
# RUN
# ----------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)