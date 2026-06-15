# ================================================================
#  IoT PLATFORM — app.py
#  Smart Home Control Panel
#  Connects to: MQTT (paho), CoAP (aiocoap), HTTP (requests)
#  v2 — optimized log structure, full original business logic
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import os
import json
import time
import threading
import asyncio
import requests
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
import paho.mqtt.client as mqtt
import aiocoap

# ── CONFIG ───────────────────────────────────────────────────────
MQTT_BROKER   = os.environ.get('MQTT_BROKER', 'localhost')
MQTT_PORT     = int(os.environ.get('MQTT_PORT', 1883))
HTTP_SERVER   = os.environ.get('HTTP_SERVER', 'localhost')
HTTP_PORT     = int(os.environ.get('HTTP_PORT', 8080))
COAP_SERVER   = os.environ.get('COAP_SERVER', 'localhost')
COAP_PORT     = int(os.environ.get('COAP_PORT', 5683))
CAMERA_IP     = os.environ.get('CAMERA_IP', '35.205.229.51')
HONEYPOT_IP   = os.environ.get('HONEYPOT_IP', '172.20.0.2')
PLATFORM_PORT = 80

CREDENTIALS = {
    'username': 'homeowner',
    'password': 'SmartHome2024'
}

KNOWN_INTERNAL_IPS = {'127.0.0.1', '::1', HONEYPOT_IP}

DEVICE_PROTOCOLS = {
    'lock':       'mqtt',  'alarm':     'mqtt',
    'thermostat': 'mqtt',  'smartplug': 'mqtt',
    'camera':     'http',  'doorbell':  'http',
    'motion':     'coap',  'lightbulb': 'coap',
}

# ── FLASK + SOCKETIO ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'honeypot_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins='*')

# ── LOGGING SETUP ────────────────────────────────────────────────
os.makedirs('/var/log/iot_platform', exist_ok=True)
plogger = logging.getLogger('platform_logger')
plogger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/iot_platform/platform.json')
fh.setFormatter(logging.Formatter('%(message)s'))
plogger.addHandler(fh)

ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
logging.getLogger().addHandler(ch)
logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger(__name__)

# ── SESSION TRACKING ─────────────────────────────────────────────
web_sessions = {}
rate_window  = defaultdict(list)

def _get_or_create_session(src_ip):
    if src_ip not in web_sessions:
        web_sessions[src_ip] = {
            'session_id':   str(uuid.uuid4()),
            'connect_time': time.time(),
            'req_count':    0,
            'endpoints':    set(),
        }
    return web_sessions[src_ip]

def _req_rate(src_ip):
    now = time.time()
    rate_window[src_ip] = [t for t in rate_window[src_ip] if now - t < 60]
    rate_window[src_ip].append(now)
    return len(rate_window[src_ip])

def _heuristic_label(src_ip, endpoint, req_rate, body_size):
    is_internal = src_ip in KNOWN_INTERNAL_IPS or src_ip.startswith('172.20.')
    if not is_internal:
        if req_rate > 30:
            return True, 'ddos'
        if any(x in endpoint for x in ['..', '/etc/', '/passwd', '/config', '/admin']):
            return True, 'path_traversal'
        if body_size > 50000:
            return True, 'large_payload'
        return True, 'unknown_external'
    return False, 'benign'

def log_platform_event(endpoint, status_code, extra=None):
    src_ip    = request.remote_addr
    body      = request.get_data()
    body_size = len(body)
    sess      = _get_or_create_session(src_ip)
    req_rate  = _req_rate(src_ip)
    sess['req_count'] += 1
    sess['endpoints'].add(endpoint)
    is_attack, attack_type = _heuristic_label(src_ip, endpoint, req_rate, body_size)

    entry = {
        # ── Common fields ──
        "@timestamp":             datetime.now(timezone.utc).isoformat(),
        "log_type":               "platform",
        "src_ip":                 src_ip,
        "dst_ip":                 HONEYPOT_IP,
        "src_port":               request.environ.get('REMOTE_PORT', 0),
        "dst_port":               PLATFORM_PORT,
        "protocol":               "HTTP",
        "bytes_sent":             body_size,
        "bytes_received":         0,
        "is_internal":            src_ip.startswith('172.20.') or src_ip == '127.0.0.1',
        "is_known_device":        False,
        "is_attack":              is_attack,
        "attack_type":            attack_type,
        "session_id":             sess['session_id'],

        # ── Platform-specific fields ──
        "http_method":            request.method,
        "http_endpoint":          endpoint,
        "http_status_code":       status_code,
        "user_agent":             request.headers.get('User-Agent', ''),
        "body_size":              body_size,

        # ── Behavioral features ──
        "session_req_count":      sess['req_count'],
        "session_endpoint_count": len(sess['endpoints']),
        "req_rate_per_min":       req_rate,
        "session_duration_s":     round(time.time() - sess['connect_time'], 2),
    }
    
    if extra:
        entry.update(extra)
    plogger.info(json.dumps(entry))
    print(f"[Platform] {request.method} {endpoint} from {src_ip} → {status_code}", flush=True)

# ── IN-MEMORY DEVICE STATE ────────────────────────────────────────
device_states = {
    'thermostat': {'temperature': '--', 'humidity': '--', 'mode': '--',
                   'last_seen': '--', 'status': 'offline'},
    'lock':       {'state': '--', 'battery': '--', 'tamper': False,
                   'last_seen': '--', 'status': 'offline'},
    'alarm':      {'state': '--', 'zone': '--', 'siren': False,
                   'last_seen': '--', 'status': 'offline'},
    'smartplug':  {'state': '--', 'power': '--', 'energy': '--',
                   'last_seen': '--', 'status': 'offline'},
    'motion':     {'motion_detected': False, 'zone': '--', 'enabled': True,
                   'last_seen': '--', 'status': 'offline'},
    'lightbulb':  {'state': '--', 'brightness': '--', 'color_temp': '--',
                   'last_seen': '--', 'status': 'offline'},
    'camera':     {'event_type': '--', 'rtsp_url': f'rtsp://{CAMERA_IP}:8554/live',
                   'night_mode': False, 'last_seen': '--', 'status': 'offline'},
    'doorbell':   {'event_type': '--', 'battery_level': '--', 'wifi_signal': '--',
                   'last_seen': '--', 'status': 'offline'},
}

# ── OFFLINE TIMEOUT CHECKER ───────────────────────────────────────
device_last_seen = {d: None for d in device_states}
OFFLINE_TIMEOUT  = 60  # seconds

def update_last_seen(device):
    device_last_seen[device] = datetime.now(timezone.utc)

def offline_checker():
    while True:
        now     = datetime.now(timezone.utc)
        changed = False
        for device, last in device_last_seen.items():
            if last is None:
                continue
            seconds_ago = (now - last).total_seconds()
            if seconds_ago > OFFLINE_TIMEOUT and device_states[device]['status'] == 'online':
                device_states[device]['status'] = 'offline'
                log.info(f"[TIMEOUT] {device} marked offline — {int(seconds_ago)}s no data")
                changed = True
        if changed:
            socketio.emit('device_update', {'device': 'timeout', 'states': device_states})
        time.sleep(10)

# ── MQTT — subscribe to all device topics ────────────────────────
def on_connect(client, userdata, flags, reason_code, properties):
    log.info("[MQTT] Connected to broker")
    client.subscribe("home/#")

def on_message(client, userdata, msg):
    try:
        topic   = msg.topic
        payload = json.loads(msg.payload.decode('utf-8'))
        now     = datetime.now(timezone.utc).strftime('%H:%M:%S')

        if topic == 'home/thermostat/temperature':
            device_states['thermostat']['temperature'] = payload.get('value', '--')
            device_states['thermostat']['last_seen']   = now
            device_states['thermostat']['status']      = 'online'
            update_last_seen('thermostat')
        elif topic == 'home/thermostat/humidity':
            device_states['thermostat']['humidity']  = payload.get('value', '--')
            device_states['thermostat']['last_seen'] = now
            device_states['thermostat']['status']    = 'online'
        elif topic == 'home/thermostat/mode':
            device_states['thermostat']['mode']      = payload.get('value', '--')
            device_states['thermostat']['last_seen'] = now
            device_states['thermostat']['status']    = 'online'
        elif topic == 'home/lock/state':
            device_states['lock']['state']     = payload.get('value', '--')
            device_states['lock']['last_seen'] = now
            device_states['lock']['status']    = 'online'
            update_last_seen('lock')
        elif topic == 'home/lock/battery':
            device_states['lock']['battery']   = payload.get('value', '--')
            device_states['lock']['last_seen'] = now
            device_states['lock']['status']    = 'online'
        elif topic == 'home/lock/tamper':
            device_states['lock']['tamper']    = payload.get('value', False)
            device_states['lock']['last_seen'] = now
            device_states['lock']['status']    = 'online'
        elif topic == 'home/alarm/state':
            device_states['alarm']['state']    = payload.get('value', '--')
            device_states['alarm']['last_seen']= now
            device_states['alarm']['status']   = 'online'
            update_last_seen('alarm')
        elif topic == 'home/alarm/zone':
            device_states['alarm']['zone']     = payload.get('zone', '--')
            device_states['alarm']['last_seen']= now
            device_states['alarm']['status']   = 'online'
        elif topic == 'home/alarm/siren':
            device_states['alarm']['siren']    = payload.get('value', False)
            device_states['alarm']['last_seen']= now
            device_states['alarm']['status']   = 'online'
        elif topic == 'home/smartplug/state':
            device_states['smartplug']['state']    = payload.get('value', '--')
            device_states['smartplug']['last_seen']= now
            device_states['smartplug']['status']   = 'online'
            update_last_seen('smartplug')
        elif topic == 'home/smartplug/power':
            device_states['smartplug']['power']    = payload.get('value', '--')
            device_states['smartplug']['last_seen']= now
            device_states['smartplug']['status']   = 'online'
        elif topic == 'home/smartplug/energy':
            device_states['smartplug']['energy']   = payload.get('value', '--')
            device_states['smartplug']['last_seen']= now
            device_states['smartplug']['status']   = 'online'

        socketio.emit('device_update', {
            'device': topic.split('/')[1],
            'states': device_states
        })
    except Exception as e:
        log.error(f"[MQTT] Error: {e}")

def start_mqtt():
    client = mqtt.Client(
        client_id='iot_platform',
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.on_connect = on_connect
    client.on_message = on_message
    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            client.loop_forever()
        except Exception as e:
            log.error(f"[MQTT] Connection failed: {e} — retrying in 5s")
            time.sleep(5)

# ── CoAP — poll motion and lightbulb ─────────────────────────────
async def poll_coap():
    await asyncio.sleep(5)
    context = await aiocoap.Context.create_client_context()
    while True:
        now = datetime.now(timezone.utc).strftime('%H:%M:%S')
        try:
            req  = aiocoap.Message(code=aiocoap.GET,
                   uri=f'coap://{COAP_SERVER}:{COAP_PORT}/home/motion')
            resp = await context.request(req).response
            data = json.loads(resp.payload.decode('utf-8'))
            updated_at = data.get('updated_at')
            if updated_at:
                dt  = datetime.fromisoformat(updated_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - dt).total_seconds()
                if age < OFFLINE_TIMEOUT:
                    device_states['motion']['motion_detected'] = data.get('motion', False)
                    device_states['motion']['zone']            = data.get('zone', '--')
                    device_states['motion']['enabled']         = data.get('enabled', True)
                    device_states['motion']['last_seen']       = data.get('last_seen', now)
                    device_states['motion']['status']          = 'online'
                    update_last_seen('motion')
        except Exception as e:
            log.warning(f"[CoAP] Motion poll failed: {e}")

        try:
            req  = aiocoap.Message(code=aiocoap.GET,
                   uri=f'coap://{COAP_SERVER}:{COAP_PORT}/home/light')
            resp = await context.request(req).response
            data = json.loads(resp.payload.decode('utf-8'))
            updated_at = data.get('updated_at')
            if updated_at:
                dt  = datetime.fromisoformat(updated_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - dt).total_seconds()
                if age < OFFLINE_TIMEOUT:
                    device_states['lightbulb']['state']      = data.get('state', '--')
                    device_states['lightbulb']['brightness'] = data.get('brightness', '--')
                    device_states['lightbulb']['color_temp'] = data.get('color_temp', '--')
                    device_states['lightbulb']['last_seen']  = data.get('last_seen', now)
                    device_states['lightbulb']['status']     = 'online'
                    update_last_seen('lightbulb')
        except Exception as e:
            log.warning(f"[CoAP] Lightbulb poll failed: {e}")

        socketio.emit('device_update', {'device': 'coap', 'states': device_states})
        await asyncio.sleep(10)

def start_coap():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(poll_coap())

# ── HTTP — poll camera and doorbell ──────────────────────────────
def poll_http():
    time.sleep(5)
    while True:
        now = datetime.now(timezone.utc).strftime('%H:%M:%S')
        try:
            resp = requests.get(
                f'http://{HTTP_SERVER}:{HTTP_PORT}/api/camera/status', timeout=3)
            if resp.status_code == 200:
                data       = resp.json()
                updated_at = data.get('updated_at')
                if updated_at:
                    dt  = datetime.fromisoformat(updated_at)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - dt).total_seconds()
                    if age < OFFLINE_TIMEOUT and data.get('event_type') != 'offline':
                        device_states['camera']['event_type'] = data.get('event_type', '--')
                        device_states['camera']['night_mode'] = data.get('night_mode', False)
                        device_states['camera']['last_seen']  = data.get('last_seen', now)
                        device_states['camera']['status']     = 'online'
                        update_last_seen('camera')
        except Exception as e:
            log.warning(f"[HTTP] Camera poll failed: {e}")

        try:
            resp = requests.get(
                f'http://{HTTP_SERVER}:{HTTP_PORT}/api/doorbell/status', timeout=3)
            if resp.status_code == 200:
                data       = resp.json()
                updated_at = data.get('updated_at')
                if updated_at:
                    dt  = datetime.fromisoformat(updated_at)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - dt).total_seconds()
                    if age < OFFLINE_TIMEOUT and data.get('event_type') != 'offline':
                        device_states['doorbell']['event_type']    = data.get('event_type', '--')
                        device_states['doorbell']['battery_level'] = data.get('battery_level', '--')
                        device_states['doorbell']['last_seen']     = data.get('last_seen', now)
                        device_states['doorbell']['status']        = 'online'
                        update_last_seen('doorbell')
        except Exception as e:
            log.warning(f"[HTTP] Doorbell poll failed: {e}")

        socketio.emit('device_update', {'device': 'http', 'states': device_states})
        time.sleep(10)

# ── ROUTES ───────────────────────────────────────────────────────
@app.route('/', methods=['GET'])
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    src_ip   = request.remote_addr
    success  = username == CREDENTIALS['username'] and password == CREDENTIALS['password']

    log_platform_event('/login', 200 if success else 401, extra={
        'login_attempt':  True,
        'login_success':  success,
        'username_tried': username,
        'password_tried': password,
    })

    if success:
        session['logged_in'] = True
        session['username']  = username
        log.info(f"[AUTH] Login success from {src_ip}")
        return redirect(url_for('dashboard'))
    else:
        log.warning(f"[AUTH] Failed login from {src_ip} — {username}:{password}")
        return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('index'))
    log_platform_event('/dashboard', 200)
    return render_template('dashboard.html')

@app.route('/api/devices', methods=['GET'])
def get_devices():
    if 'logged_in' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    log_platform_event('/api/devices', 200)
    return jsonify(device_states)

@app.route('/api/camera/stream', methods=['GET'])
def camera_stream():
    if 'logged_in' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    log_platform_event('/api/camera/stream', 200)
    return jsonify({
        'rtsp_url': f'rtsp://{CAMERA_IP}:8554/live',
        'status':   device_states['camera']['status']
    })

@app.route('/api/command', methods=['POST'])
def send_command():
    if 'logged_in' not in session:
        log_platform_event('/api/command', 401, extra={'reason': 'not logged in'})
        return jsonify({'error': 'unauthorized'}), 401

    t0      = time.time()
    data    = request.get_json()
    device  = data.get('device')
    command = data.get('command')
    src_ip  = request.remote_addr

    try:
        if device in ['thermostat', 'lock', 'alarm', 'smartplug']:
            topic = f'home/{device}/command'
            mqtt_client.publish(topic, json.dumps({'command': command}))
            ms = round((time.time() - t0) * 1000, 2)
            log_platform_event('/api/command', 200, extra={
                'target_device': device, 'command': command,
                'device_protocol': 'mqtt', 'mqtt_topic': topic,
                'session_user': session.get('username', 'unknown'),
                'response_time_ms': ms,
            })
            return jsonify({'status': 'ok', 'device': device, 'command': command})

        elif device in ['camera', 'doorbell']:
            resp = requests.post(
                f'http://{HTTP_SERVER}:{HTTP_PORT}/api/{device}/command',
                json={'command': command}, timeout=3)
            ms = round((time.time() - t0) * 1000, 2)
            log_platform_event('/api/command', 200, extra={
                'target_device': device, 'command': command,
                'device_protocol': 'http',
                'http_endpoint': f'/api/{device}/command',
                'session_user': session.get('username', 'unknown'),
                'response_time_ms': ms,
            })
            return jsonify({'status': 'ok', 'response': resp.json()})

        elif device in ['motion', 'lightbulb']:
            asyncio.run(send_coap_command(device, command))
            ms = round((time.time() - t0) * 1000, 2)
            log_platform_event('/api/command', 200, extra={
                'target_device': device, 'command': command,
                'device_protocol': 'coap',
                'coap_path': f"home/{'motion' if device == 'motion' else 'light'}/command",
                'session_user': session.get('username', 'unknown'),
                'response_time_ms': ms,
            })
            return jsonify({'status': 'ok', 'device': device, 'command': command})

        else:
            log_platform_event('/api/command', 400, extra={
                'target_device': device, 'command': command, 'reason': 'unknown device'
            })
            return jsonify({'error': 'unknown device'}), 400

    except Exception as e:
        log_platform_event('/api/command', 500, extra={
            'target_device': device, 'command': command, 'error': str(e)
        })
        return jsonify({'error': str(e)}), 500

async def send_coap_command(device, command):
    resource_map = {'motion': 'home/motion/command', 'lightbulb': 'home/light/command'}
    context = await aiocoap.Context.create_client_context()
    payload = json.dumps({'command': command}).encode('utf-8')
    req = aiocoap.Message(
        code=aiocoap.POST,
        uri=f'coap://{COAP_SERVER}:{COAP_PORT}/{resource_map[device]}',
        payload=payload
    )
    await context.request(req).response

@app.route('/logout')
def logout():
    log_platform_event('/logout', 200, extra={
        'session_user': session.get('username', 'unknown')
    })
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    log_platform_event(request.path, 404)
    return jsonify({'error': 'not found'}), 404

# ── SOCKETIO ─────────────────────────────────────────────────────
@socketio.on('connect')
def on_socketio_connect():
    emit('device_update', {'device': 'init', 'states': device_states})

# ── BACKGROUND SERVICES ──────────────────────────────────────────
mqtt_client = mqtt.Client(
    client_id='iot_platform_cmd',
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2
)

def start_background_services():
    threading.Thread(target=start_mqtt,      daemon=True).start()
    threading.Thread(target=start_coap,      daemon=True).start()
    threading.Thread(target=poll_http,       daemon=True).start()
    threading.Thread(target=offline_checker, daemon=True).start()
    try:
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        log.error(f"[MQTT CMD] Connection failed: {e}")

# ── MAIN ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    start_background_services()
    socketio.run(app, host='0.0.0.0', port=PLATFORM_PORT, debug=False)