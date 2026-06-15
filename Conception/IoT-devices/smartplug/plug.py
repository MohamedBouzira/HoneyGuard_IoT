# ================================================================
#  SIM-SMARTPLUG — MQTT Simulator
#  Publishes power state, wattage, energy consumption
#  Listens on home/smartplug/command for commands from IoT platform
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import os
import json
import time
import random
import paho.mqtt.client as mqtt
from datetime import datetime

#waiting for Service to run
time.sleep(10)

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
BROKER      = os.environ.get('BROKER', '172.20.0.2')
BROKER_PORT = int(os.environ.get('BROKER_PORT', 1883))
DEVICE_ID   = os.environ.get('DEVICE_ID', 'smartplug_01')
INTERVAL    = 30

TOPIC_STATE   = "home/smartplug/state"
TOPIC_POWER   = "home/smartplug/power"
TOPIC_ENERGY  = "home/smartplug/energy"
TOPIC_COMMAND = "home/smartplug/command"

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "on": True    # starts on
}

total_energy = 0.0

# ----------------------------------------------------------------
# CALLBACKS
# ----------------------------------------------------------------
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[{DEVICE_ID}] Connected to broker {BROKER}:{BROKER_PORT}", flush=True)
        client.subscribe(TOPIC_COMMAND)
        print(f"[{DEVICE_ID}] Subscribed to {TOPIC_COMMAND}", flush=True)
    else:
        print(f"[{DEVICE_ID}] Connection failed: {reason_code}", flush=True)

def on_disconnect(client, userdata, flags, reason_code, properties):
    print(f"[{DEVICE_ID}] Disconnected — retrying...", flush=True)

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode('utf-8')
        print(f"[{DEVICE_ID}] Command received: {payload}", flush=True)

        data    = json.loads(payload)
        command = data.get("command", payload)

        if command == "on":
            state["on"] = True
            print(f"[{DEVICE_ID}] Turned ON", flush=True)

        elif command == "off":
            state["on"] = False
            print(f"[{DEVICE_ID}] Turned OFF", flush=True)

        else:
            print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

    except Exception as e:
        print(f"[{DEVICE_ID}] Command parse error: {e}", flush=True)

# ----------------------------------------------------------------
# DATA SIMULATION
# when off — power is 0, energy stops accumulating
# ----------------------------------------------------------------
def get_power():
    if not state["on"]:
        return 0.0
    return round(random.uniform(200, 2500), 1)

def get_energy(power):
    global total_energy
    total_energy += (power * (INTERVAL / 3600)) / 1000
    return round(total_energy, 4)

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    client = mqtt.Client(
        client_id=DEVICE_ID,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    while True:
        try:
            client.connect(BROKER, BROKER_PORT, keepalive=60)
            break
        except Exception as e:
            print(f"[{DEVICE_ID}] Broker not ready, retrying in 5s... ({e})", flush=True)
            time.sleep(5)

    client.loop_start()
    print(f"[{DEVICE_ID}] Starting publish loop every {INTERVAL}s", flush=True)

    while True:
        timestamp = datetime.utcnow().isoformat()
        power     = get_power()

        client.publish(TOPIC_STATE, json.dumps({
            "device_id": DEVICE_ID,
            "value":     "on" if state["on"] else "off",
            "timestamp": timestamp
        }))

        client.publish(TOPIC_POWER, json.dumps({
            "device_id": DEVICE_ID,
            "value":     power,
            "unit":      "watts",
            "timestamp": timestamp
        }))

        client.publish(TOPIC_ENERGY, json.dumps({
            "device_id": DEVICE_ID,
            "value":     get_energy(power),
            "unit":      "kWh",
            "timestamp": timestamp
        }))

        print(f"[{DEVICE_ID}] Published — state:{'on' if state['on'] else 'off'} power:{power}W", flush=True)
        time.sleep(INTERVAL)

if __name__ == '__main__':
    main()