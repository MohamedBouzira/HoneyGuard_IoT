#!/usr/bin/env python3
# ================================================================
#  TSHARK NETWORK MONITOR — tshark_to_json.py
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import json
import logging
import os
import subprocess
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

# ── CONFIG ───────────────────────────────────────────────────────
HONEYPOT_IP   = os.environ.get('HONEYPOT_IP', '172.20.0.2')
INTERFACE     = os.environ.get('CAPTURE_IFACE', 'eth0')
LOG_PATH      = '/var/log/tshark/packets.json'

COVERED_PORTS = {80, 1883, 8080, 5683, 22, 23}

SYN_THRESHOLD   = 20
SCAN_THRESHOLD  = 8
ICMP_THRESHOLD  = 10
FLOOD_THRESHOLD = 80
WINDOW_SECONDS  = 15

KNOWN_INTERNAL = {
    '172.20.0.1',  '172.20.0.2',  '172.20.0.10', '172.20.0.11',
    '172.20.0.12', '172.20.0.13', '172.20.0.14', '172.20.0.15',
    '172.20.0.16', '172.20.0.17',
}

# ── LOGGING SETUP ────────────────────────────────────────────────
os.makedirs('/var/log/tshark', exist_ok=True)
logger = logging.getLogger('tshark_monitor')
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_PATH)
fh.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(fh)

# ── AGGREGATION STATE ────────────────────────────────────────────
syn_counter  = defaultdict(int)
icmp_counter = defaultdict(int)
pkt_counter  = defaultdict(int)
port_scanner = defaultdict(set)
last_flush   = time.time()

# ── ATTACK WRITER ────────────────────────────────────────────────
def write_attack(timestamp, src_ip, attack_name, attack_type,
                 packet_count=0, pps=0.0, scanned_ports=None,
                 protocol='TCP'):
    entry = {
        # ── Common fields ──
        "@timestamp":      timestamp,
        "log_type":        "network",
        "src_ip":          src_ip,
        "dst_ip":          HONEYPOT_IP,
        "src_port":        0,
        "dst_port":        0,
        "protocol":        protocol,
        "bytes_sent":      0,
        "bytes_received":  0,
        "is_internal":     False,
        "is_known_device": False,
        "is_attack":       True,
        "attack_type":     attack_type,
        "session_id":      str(uuid.uuid4()),

        # ── Network-specific fields ──
        "attack_name":     attack_name,
        "packet_count":    packet_count,
        "pps":             pps,
        "scanned_ports":   scanned_ports or [],
        "window_seconds":  WINDOW_SECONDS,
    }
    logger.info(json.dumps(entry))
    print(f"[TSHARK] ATTACK: {attack_name} from {src_ip} "
          f"({packet_count} pkts @ {pps} pps)", flush=True)

# ── FLUSH & DETECT ───────────────────────────────────────────────
def flush_and_detect():
    global last_flush
    now_ts = datetime.now(timezone.utc).isoformat()

    all_ips = set(
        list(syn_counter) + list(icmp_counter) +
        list(pkt_counter) + list(port_scanner)
    )

    for src_ip in all_ips:
        if src_ip in KNOWN_INTERNAL:
            continue

        syn_count  = syn_counter.get(src_ip, 0)
        icmp_count = icmp_counter.get(src_ip, 0)
        pkt_count  = pkt_counter.get(src_ip, 0)
        ports      = port_scanner.get(src_ip, set())

        print(f"[TSHARK] FLUSH — {src_ip}: "
              f"ports={len(ports)} syn={syn_count} "
              f"icmp={icmp_count} pkts={pkt_count}", flush=True)

        if len(ports) >= SCAN_THRESHOLD:
            write_attack(now_ts, src_ip, 'port_scan', 'port_scan',
                         packet_count=len(ports),
                         pps=round(pkt_count / WINDOW_SECONDS, 2),
                         scanned_ports=sorted(list(ports))[:50])

        if syn_count >= SYN_THRESHOLD:
            write_attack(now_ts, src_ip, 'syn_flood', 'ddos',
                         packet_count=syn_count,
                         pps=round(syn_count / WINDOW_SECONDS, 2),
                         protocol='TCP')

        if icmp_count >= ICMP_THRESHOLD:
            write_attack(now_ts, src_ip, 'icmp_flood', 'ddos',
                         packet_count=icmp_count,
                         pps=round(icmp_count / WINDOW_SECONDS, 2),
                         protocol='ICMP')

        if (pkt_count >= FLOOD_THRESHOLD
                and syn_count < SYN_THRESHOLD
                and icmp_count < ICMP_THRESHOLD
                and len(ports) < SCAN_THRESHOLD):
            write_attack(now_ts, src_ip, 'packet_flood', 'ddos',
                         packet_count=pkt_count,
                         pps=round(pkt_count / WINDOW_SECONDS, 2))

    syn_counter.clear()
    icmp_counter.clear()
    pkt_counter.clear()
    port_scanner.clear()
    last_flush = time.time()

# ── PACKET PARSER ────────────────────────────────────────────────
def get_field(layer, key):
    """Safely extract a field that might be a list or scalar."""
    val = layer.get(key, '')
    if isinstance(val, list):
        val = val[0] if val else ''
    return val

def process_packet(layers):
    global last_flush

    ip_layer  = layers.get('ip', {})
    ip6_layer = layers.get('ipv6', {})
    src_ip    = get_field(ip_layer, 'ip.src') or get_field(ip6_layer, 'ipv6.src')

    if not src_ip:
        return

    tcp = layers.get('tcp', {})
    udp = layers.get('udp', {})

    dst_port = int(get_field(tcp, 'tcp.dstport') or get_field(udp, 'udp.dstport') or 0)
    src_port = int(get_field(tcp, 'tcp.srcport') or get_field(udp, 'udp.srcport') or 0)

    # Port scan — track ALL destination ports probed by this IP
    if dst_port > 0:
        port_scanner[src_ip].add(dst_port)

    # SYN flood — SYN set, ACK not set
    flags_hex = get_field(tcp, 'tcp.flags')
    if flags_hex:
        try:
            flag_val = int(str(flags_hex), 16)
            if (flag_val & 0x02) and not (flag_val & 0x10):
                syn_counter[src_ip] += 1
        except Exception:
            pass

    # ICMP flood
    if 'icmp' in layers or 'icmpv6' in layers:
        icmp_counter[src_ip] += 1

    # General flood — skip covered ports to reduce IoT noise
    if dst_port not in COVERED_PORTS and src_port not in COVERED_PORTS:
        pkt_counter[src_ip] += 1

    if time.time() - last_flush >= WINDOW_SECONDS:
        flush_and_detect()

# ── MAIN CAPTURE LOOP ────────────────────────────────────────────
def run_capture():
    # Use pdml-style line output instead of full JSON array
    # -l flushes after each packet — real-time processing
    # -T json -e fields gives us structured per-packet output
    cmd = [
        'tshark',
        '-i', INTERFACE,
        '-T', 'json',
        '-f', 'ip',
        '--no-duplicate-keys',
        '-l',                        # line buffered — flush per packet
    ]

    print(f"[TSHARK] Starting on {INTERFACE} "
          f"(scan>={SCAN_THRESHOLD}p, syn>={SYN_THRESHOLD}, "
          f"icmp>={ICMP_THRESHOLD}, flood>={FLOOD_THRESHOLD} "
          f"in {WINDOW_SECONDS}s)", flush=True)

    while True:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            buffer = ''
            depth  = 0
            in_obj = False

            for line in proc.stdout:
                # tshark -T json outputs a JSON array — we parse
                # object by object by tracking brace depth
                for ch in line:
                    if ch == '{':
                        depth += 1
                        in_obj = True
                    if in_obj:
                        buffer += ch
                    if ch == '}':
                        depth -= 1
                        if depth == 0 and in_obj:
                            # Complete JSON object — parse it
                            try:
                                pkt = json.loads(buffer)
                                layers = pkt.get('_source', {}).get('layers', {})
                                if isinstance(layers, dict):
                                    process_packet(layers)
                            except Exception:
                                pass
                            buffer = ''
                            in_obj = False

                # Check window every line
                if time.time() - last_flush >= WINDOW_SECONDS:
                    flush_and_detect()

            proc.wait()

        except Exception as e:
            print(f"[TSHARK] Error: {e} — restarting in 5s", flush=True)
            time.sleep(5)

if __name__ == '__main__':
    run_capture()