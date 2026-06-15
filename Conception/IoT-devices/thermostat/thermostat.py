# ================================================================
#  SIM-THERMOSTAT — MQTT Simulator
#  Publishes temperature, humidity, mode to separate topics
#  Listens on home/thermostat/command for commands from IoT platform
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
DEVICE_ID   = os.environ.get('DEVICE_ID', 'thermostat_01')
INTERVAL    = 30

TOPIC_TEMP     = "home/thermostat/temperature"
TOPIC_HUMIDITY = "home/thermostat/humidity"
TOPIC_MODE     = "home/thermostat/mode"
TOPIC_COMMAND  = "home/thermostat/command"

# ----------------------------------------------------------------
# DEVICE STATE
# this is what the simulator acts on
# commands from IoT platform change these values
# ----------------------------------------------------------------
state = {
    "mode":        "auto",
    "target_temp": 22.0
}

# ----------------------------------------------------------------
# MQTT CALLBACKS
# ----------------------------------------------------------------
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[{DEVICE_ID}] Connected to broker {BROKER}:{BROKER_PORT}", flush=True)
        # subscribe to command topic right after connecting
        client.subscribe(TOPIC_COMMAND)
        print(f"[{DEVICE_ID}] Subscribed to {TOPIC_COMMAND}", flush=True)
    else:
        print(f"[{DEVICE_ID}] Connection failed: {reason_code}", flush=True)

def on_disconnect(client, userdata, flags, reason_code, properties):
    print(f"[{DEVICE_ID}] Disconnected — retrying...", flush=True)

def on_message(client, userdata, msg):
    """Called instantly when IoT platform publishes a command"""
    try:
        topic   = msg.topic
        payload = msg.payload.decode('utf-8')
        print(f"[{DEVICE_ID}] Command received: {payload}", flush=True)

        data    = json.loads(payload)
        command = data.get("command", payload)

        # set_mode:cooling / set_mode:heating / set_mode:off / set_mode:auto
        if command.startswith("set_mode:"):
            new_mode       = command.split(":")[1]
            state["mode"]  = new_mode
            print(f"[{DEVICE_ID}] Mode changed to: {new_mode}", flush=True)

        # set_temp:22.5
        elif command.startswith("set_temp:"):
            new_temp             = float(command.split(":")[1])
            state["target_temp"] = new_temp
            print(f"[{DEVICE_ID}] Target temp changed to: {new_temp}", flush=True)

        else:
            print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

    except Exception as e:
        print(f"[{DEVICE_ID}] Command parse error: {e}", flush=True)

# ----------------------------------------------------------------
# DATA SIMULATION
# temperature drifts toward target based on mode
# ----------------------------------------------------------------
current_temp = round(random.uniform(18.0, 26.0), 1)

def get_temperature():
    global current_temp
    if state["mode"] == "heating":
        current_temp = min(current_temp + random.uniform(0.1, 0.5), 30.0)
    elif state["mode"] == "cooling":
        current_temp = max(current_temp - random.uniform(0.1, 0.5), 16.0)
    else:
        current_temp += random.uniform(-0.3, 0.3)
        current_temp = round(max(16.0, min(30.0, current_temp)), 1)
    return round(current_temp, 1)

def get_humidity():
    return round(random.uniform(40.0, 70.0), 1)

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

        client.publish(TOPIC_TEMP, json.dumps({
            "device_id": DEVICE_ID,
            "value":     get_temperature(),
            "unit":      "celsius",
            "timestamp": timestamp
        }))

        client.publish(TOPIC_HUMIDITY, json.dumps({
            "device_id": DEVICE_ID,
            "value":     get_humidity(),
            "unit":      "percent",
            "timestamp": timestamp
        }))

        client.publish(TOPIC_MODE, json.dumps({
            "device_id": DEVICE_ID,
            "value":     state["mode"],
            "timestamp": timestamp
        }))

        print(f"[{DEVICE_ID}] Published — temp:{current_temp} mode:{state['mode']}", flush=True)
        time.sleep(INTERVAL)

if __name__ == '__main__':
    main()