# ================================================================
#  MQTT LOGGER — mqtt_logger.py
#  Subscribes to ALL topics on the broker
#  Logs every message with full metadata for AI training
#  v2 - optimized log structure
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
import paho.mqtt.client as mqtt

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
BROKER_HOST  = os.environ.get('MQTT_BROKER', 'localhost')
BROKER_PORT  = int(os.environ.get('MQTT_PORT', 1883))
HONEYPOT_IP  = os.environ.get('HONEYPOT_IP', '172.20.0.2')

KNOWN_CLIENTS = {
    'thermostat_01', 'alarm_01',
    'smartplug_01',  'smart_lock_01',
    'lock_01',       'alarm_system_01',
    'iot_platform',  'iot_platform_cmd',
    'mqtt_logger',
}

TOPIC_DEVICE_MAP = {
    'thermostat': 'thermostat_01',
    'lock':       'smart_lock_01',
    'alarm':      'alarm_system_01',
    'smartplug':  'smartplug_01',    
}

KNOWN_TOPICS = {
    'home/thermostat/temperature', 'home/thermostat/humidity',
    'home/thermostat/mode',        'home/thermostat/command',
    'home/lock/state',             'home/lock/battery',
    'home/lock/tamper',            'home/lock/command',
    'home/alarm/state',            'home/alarm/zone',
    'home/alarm/siren',            'home/alarm/command',
    'home/smartplug/state',        'home/smartplug/power',
    'home/smartplug/energy',       'home/smartplug/command',
}

# Skip high-frequency heartbeat topics from known devices
HEARTBEAT_TOPICS = {
    'home/thermostat/temperature', 'home/thermostat/humidity',
    'home/smartplug/power',        'home/smartplug/energy',
}

# ----------------------------------------------------------------
# LOGGING SETUP
# ----------------------------------------------------------------
os.makedirs('/var/log/mqtt', exist_ok=True)
logger = logging.getLogger('mqtt_logger')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/mqtt/mqtt.json')
fh.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(fh)

# ── SESSION TRACKING ─────────────────────────────────────────────
sessions    = {}
rate_window = defaultdict(list)

def _get_or_create_session(client_id):
    if client_id not in sessions:
        sessions[client_id] = {
            'session_id':   str(uuid.uuid4()),
            'connect_time': time.time(),
            'msg_count':    0,
            'topics':       set(),
        }
    return sessions[client_id]

def _msg_rate(client_id):
    now = time.time()
    rate_window[client_id] = [t for t in rate_window[client_id] if now - t < 60]
    rate_window[client_id].append(now)
    return len(rate_window[client_id])

def _heuristic_label(is_known_client, is_known_topic, topic, msg_rate):
    if not is_known_client:
        if msg_rate > 50:
            return True, 'ddos'
        if '#' in topic or '+' in topic:
            return True, 'wildcard_scan'
        return True, 'unknown_client'
    if not is_known_topic:
        return True, 'topic_anomaly'
    if msg_rate > 100:
        return True, 'ddos'
    return False, 'benign'

# ── CORE LOG FUNCTION ────────────────────────────────────────────
def log_event(client_id, topic, payload_raw, qos, retain, mqtt_action):
    is_known_client = client_id in KNOWN_CLIENTS
    is_known_topic  = topic in KNOWN_TOPICS

    # Skip internal device heartbeats
    if is_known_client and topic in HEARTBEAT_TOPICS:
        return

    session      = _get_or_create_session(client_id)
    msg_rate     = _msg_rate(client_id)
    payload_size = len(payload_raw.encode('utf-8', errors='replace'))

    session['msg_count'] += 1
    session['topics'].add(topic)

    store_payload = not is_known_client or not is_known_topic
    payload_field = payload_raw[:512] if store_payload and payload_size > 0 else None

    is_attack, attack_type = _heuristic_label(
        is_known_client, is_known_topic, topic, msg_rate
    )

    entry = {
        # ── Common fields ──
        "@timestamp":          datetime.now(timezone.utc).isoformat(),
        "log_type":            "mqtt",
        "src_ip":              HONEYPOT_IP,
        "dst_ip":              HONEYPOT_IP,
        "src_port":            0,
        "dst_port":            BROKER_PORT,
        "protocol":            "MQTT",
        "bytes_sent":          payload_size,
        "bytes_received":      0,
        "is_internal":         is_known_client,
        "is_known_device":     is_known_client,
        "is_attack":           is_attack,
        "attack_type":         attack_type,
        "session_id":          session['session_id'],

        # ── MQTT-specific fields ──
        "mqtt_action":         mqtt_action,
        "client_id":           client_id,
        "topic":               topic,
        "payload":             payload_field,
        "payload_size":        payload_size,
        "qos":                 qos,
        "retain":              int(retain),
        "is_known_topic":      is_known_topic,

        # ── Behavioral features ──
        "session_msg_count":   session['msg_count'],
        "session_topic_count": len(session['topics']),
        "msg_rate_per_min":    msg_rate,
        "session_duration_s":  round(time.time() - session['connect_time'], 2),
    }

    logger.info(json.dumps(entry))

# ── MQTT CALLBACKS ───────────────────────────────────────────────
def on_connect(client, userdata, flags, reason_code, properties):
    print("[MQTT-LOG] Connected to broker", flush=True)
    client.subscribe('#', qos=0)

def on_message(client, userdata, msg):
    try:
        topic       = msg.topic
        payload_raw = msg.payload.decode('utf-8', errors='replace')
        parts       = topic.split('/')
        subtopic    = parts[-1] if parts else ''
        mqtt_action = 'command' if subtopic == 'command' else 'publish'

        # Map topic device name → real client_id
        device_name = parts[1] if len(parts) >= 2 else 'unknown'
        client_id   = TOPIC_DEVICE_MAP.get(device_name, device_name)

        log_event(
            client_id   = client_id,
            topic       = topic,
            payload_raw = payload_raw,
            qos         = msg.qos,
            retain      = msg.retain,
            mqtt_action = mqtt_action,
        )
    except Exception as e:
        print(f"[MQTT-LOG] Error: {e}", flush=True)

# ── MAIN ─────────────────────────────────────────────────────────
def main():
    client = mqtt.Client(
        client_id='mqtt_logger',
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.on_connect = on_connect
    client.on_message = on_message
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            client.loop_forever()
        except Exception as e:
            print(f"[MQTT-LOG] Connection failed: {e} — retrying in 5s", flush=True)
            time.sleep(5)

if __name__ == '__main__':
    main()