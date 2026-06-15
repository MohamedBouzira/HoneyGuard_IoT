# ================================================================
#  CoAP SERVER — coap_server.py
#  Serves CoAP requests from sim-motion and sim-lightbulb
#  Stores last known state — IoT platform polls via GET
#  Stores pending commands — simulators poll via GET /command
#  Schema v2 — optimized for XGBoost / Autoencoder / RL
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import asyncio
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import aiocoap
import aiocoap.resource as resource

# ── CONFIG ───────────────────────────────────────────────────────
HONEYPOT_IP = os.environ.get('HONEYPOT_IP', '172.20.0.2')
COAP_PORT   = int(os.environ.get('COAP_PORT', 5683))

KNOWN_DEVICES = {
    '172.20.0.15',  # sim-motion
    '172.20.0.17',  # sim-lightbulb
    '172.20.0.2',   # main-server (IoT platform)
    '127.0.0.1',
}

KNOWN_PATHS = {
    'home/motion',
    'home/motion/command',
    'home/light',
    'home/light/command',
}

# ── LOGGING SETUP ────────────────────────────────────────────────
os.makedirs('/var/log/coap', exist_ok=True)
logger = logging.getLogger('coap_server')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/coap/coap.json')
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
            'paths':        set(),
        }
    return sessions[src_ip]

def _req_rate(src_ip):
    now = time.time()
    rate_window[src_ip] = [t for t in rate_window[src_ip] if now - t < 60]
    rate_window[src_ip].append(now)
    return len(rate_window[src_ip])

def _heuristic_label(src_ip, path, req_rate):
    is_known      = src_ip in KNOWN_DEVICES
    is_known_path = path in KNOWN_PATHS
    if not is_known:
        if req_rate > 30:
            return True, 'ddos'
        if not is_known_path:
            return True, 'path_scan'
        return True, 'unknown'
    if req_rate > 60:
        return True, 'ddos'
    return False, 'benign'

def parse_src(remote):
    try:
        # aiocoap remote address — extract just the IP
        host = remote.hostinfo          # e.g. "127.0.0.1" or "[::1]" or "172.20.0.15"
        host = host.strip('[]')         # strip IPv6 brackets if present
        # if it still contains port (host:port), split it
        if host.count(':') == 1:        # IPv4 with port
            host, port = host.rsplit(':', 1)
            return host, int(port)
        return host, 0
    except Exception:
        try:
            # fallback: convert to string and extract IP
            s = str(remote)
            # matches patterns like "<UDP6EndpointAddress 127.0.0.1:58305 ...>"
            import re
            m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', s)
            if m:
                return m.group(1), 0
        except Exception:
            pass
        return "0.0.0.0", 0

# ── CORE LOG FUNCTION ────────────────────────────────────────────
def log_request(remote, path, method, payload_raw, response_code, extra=None):
    src_ip, src_port    = parse_src(remote)
    is_known_device     = src_ip in KNOWN_DEVICES
    is_known_path       = path in KNOWN_PATHS
    payload_size        = len(payload_raw) if payload_raw else 0
    session             = _get_or_create_session(src_ip)
    req_rate            = _req_rate(src_ip)

    session['req_count'] += 1
    session['paths'].add(path)

    is_attack, attack_type = _heuristic_label(src_ip, path, req_rate)

    # Store payload only for suspicious events, capped at 512 bytes
    store_payload = not is_known_device or is_attack
    payload_field = None
    if store_payload and payload_raw:
        try:
            payload_field = json.loads(payload_raw[:512])
        except Exception:
            payload_field = payload_raw[:512].decode('utf-8', errors='replace')

    entry = {
        # ── Common fields ──
        "@timestamp":          datetime.now(timezone.utc).isoformat(),
        "log_type":            "coap",
        "src_ip":              src_ip,
        "dst_ip":              HONEYPOT_IP,
        "src_port":            src_port,
        "dst_port":            COAP_PORT,
        "protocol":            "CoAP",
        "bytes_sent":          payload_size,
        "bytes_received":      0,
        "is_internal":         src_ip.startswith('172.20.') or src_ip == '127.0.0.1',
        "is_known_device":     is_known_device,
        "is_attack":           is_attack,
        "attack_type":         attack_type,
        "session_id":          session['session_id'],

        # ── CoAP-specific fields ──
        "coap_method":         method,
        "coap_path":           path,
        "coap_response_code":  str(response_code),
        "is_known_path":       is_known_path,
        "payload_size":        payload_size,
        "payload":             payload_field,

        # ── Behavioral features ──
        "session_req_count":   session['req_count'],
        "session_path_count":  len(session['paths']),
        "req_rate_per_min":    req_rate,
        "session_duration_s":  round(time.time() - session['connect_time'], 2),
    }
    if extra:
        entry.update(extra)

    logger.info(json.dumps(entry))
    print(f"[CoAP] {method} {path} from {src_ip} → {response_code}", flush=True)

# ── IN-MEMORY STATE STORE ────────────────────────────────────────
device_state = {
    "motion": {
        "motion":     False,
        "zone":       "--",
        "enabled":    True,
        "last_seen":  "--",
        "updated_at": None
    },
    "light": {
        "state":      "off",
        "brightness": 0,
        "color_temp": "--",
        "last_seen":  "--",
        "updated_at": None
    }
}

pending_commands = {
    "motion": None,
    "light":  None
}

# ── MOTION RESOURCE — /home/motion ───────────────────────────────
class MotionResource(resource.Resource):

    async def render_post(self, request):
        payload = request.payload
        extra   = {}
        try:
            data = json.loads(payload.decode('utf-8', errors='ignore'))
            device_state["motion"]["motion"]     = data.get("motion", False)
            device_state["motion"]["zone"]       = data.get("zone", "--")
            device_state["motion"]["enabled"]    = data.get("enabled", True)
            device_state["motion"]["last_seen"]  = datetime.now(timezone.utc).strftime('%H:%M:%S')
            device_state["motion"]["updated_at"] = datetime.now(timezone.utc).isoformat()
            extra = {
                "device":    "motion",
                "motion":    data.get("motion"),
                "zone":      data.get("zone"),
                "enabled":   data.get("enabled"),
                "device_id": data.get("device_id"),
            }
        except Exception as e:
            print(f"[CoAP] Motion parse error: {e}", flush=True)

        log_request(request.remote, 'home/motion', 'POST',
                    payload, aiocoap.CHANGED, extra)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=b'ok')

    async def render_get(self, request):
        payload = json.dumps(device_state["motion"]).encode('utf-8')
        log_request(request.remote, 'home/motion', 'GET',
                    None, aiocoap.CONTENT, {"device": "motion"})
        return aiocoap.Message(code=aiocoap.CONTENT, payload=payload)


# ── MOTION COMMAND RESOURCE — /home/motion/command ───────────────
class MotionCommandResource(resource.Resource):

    async def render_post(self, request):
        payload = request.payload
        command = None
        try:
            data    = json.loads(payload.decode('utf-8', errors='ignore'))
            command = data.get("command")
            pending_commands["motion"] = command
        except Exception as e:
            print(f"[CoAP] Motion command parse error: {e}", flush=True)

        log_request(request.remote, 'home/motion/command', 'POST',
                    payload, aiocoap.CHANGED,
                    {"device": "motion", "command": command})
        return aiocoap.Message(code=aiocoap.CHANGED, payload=b'ok')

    async def render_get(self, request):
        cmd = pending_commands["motion"]
        pending_commands["motion"] = None
        response_payload = json.dumps({"command": cmd}).encode('utf-8')
        log_request(request.remote, 'home/motion/command', 'GET',
                    None, aiocoap.CONTENT,
                    {"device": "motion", "command_sent": cmd})
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response_payload)


# ── LIGHT RESOURCE — /home/light ────────────────────────────────
class LightResource(resource.Resource):

    async def render_post(self, request):
        payload = request.payload
        extra   = {}
        try:
            data = json.loads(payload.decode('utf-8', errors='ignore'))
            device_state["light"]["state"]      = data.get("state", "off")
            device_state["light"]["brightness"] = data.get("brightness", 0)
            device_state["light"]["color_temp"] = data.get("color_temp", "--")
            device_state["light"]["last_seen"]  = datetime.now(timezone.utc).strftime('%H:%M:%S')
            device_state["light"]["updated_at"] = datetime.now(timezone.utc).isoformat()
            extra = {
                "device":     "lightbulb",
                "state":      data.get("state"),
                "brightness": data.get("brightness"),
                "color_temp": data.get("color_temp"),
                "device_id":  data.get("device_id"),
            }
        except Exception as e:
            print(f"[CoAP] Light parse error: {e}", flush=True)

        log_request(request.remote, 'home/light', 'POST',
                    payload, aiocoap.CHANGED, extra)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=b'ok')

    async def render_get(self, request):
        payload = json.dumps(device_state["light"]).encode('utf-8')
        log_request(request.remote, 'home/light', 'GET',
                    None, aiocoap.CONTENT, {"device": "lightbulb"})
        return aiocoap.Message(code=aiocoap.CONTENT, payload=payload)


# ── LIGHT COMMAND RESOURCE — /home/light/command ────────────────
class LightCommandResource(resource.Resource):

    async def render_post(self, request):
        payload = request.payload
        command = None
        try:
            data    = json.loads(payload.decode('utf-8', errors='ignore'))
            command = data.get("command")
            pending_commands["light"] = command
        except Exception as e:
            print(f"[CoAP] Light command parse error: {e}", flush=True)

        log_request(request.remote, 'home/light/command', 'POST',
                    payload, aiocoap.CHANGED,
                    {"device": "lightbulb", "command": command})
        return aiocoap.Message(code=aiocoap.CHANGED, payload=b'ok')

    async def render_get(self, request):
        cmd = pending_commands["light"]
        pending_commands["light"] = None
        response_payload = json.dumps({"command": cmd}).encode('utf-8')
        log_request(request.remote, 'home/light/command', 'GET',
                    None, aiocoap.CONTENT,
                    {"device": "lightbulb", "command_sent": cmd})
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response_payload)


# ── CATCH-ALL — log attacker probing unknown paths ───────────────
class CatchAllResource(resource.Resource):

    async def render_get(self, request):
        log_request(request.remote, 'unknown', 'GET',
                    None, aiocoap.NOT_FOUND, {})
        return aiocoap.Message(code=aiocoap.NOT_FOUND, payload=b'not found')

    async def render_post(self, request):
        log_request(request.remote, 'unknown', 'POST',
                    request.payload, aiocoap.NOT_FOUND, {})
        return aiocoap.Message(code=aiocoap.NOT_FOUND, payload=b'not found')


# ── MAIN ─────────────────────────────────────────────────────────
async def main():
    root = resource.Site()

    root.add_resource(['home', 'motion'],            MotionResource())
    root.add_resource(['home', 'motion', 'command'], MotionCommandResource())
    root.add_resource(['home', 'light'],             LightResource())
    root.add_resource(['home', 'light', 'command'],  LightCommandResource())
    root.add_resource(['.well-known', 'core'],       resource.WKCResource(root.get_resources_as_linkheader))

    print(f"[CoAP] Server running on port {COAP_PORT}", flush=True)
    await aiocoap.Context.create_server_context(root, bind=('0.0.0.0', COAP_PORT))
    await asyncio.get_event_loop().create_future()

if __name__ == '__main__':
    asyncio.run(main())