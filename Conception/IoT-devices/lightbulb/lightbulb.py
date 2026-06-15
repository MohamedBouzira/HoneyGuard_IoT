# ================================================================
#  SIM-LIGHTBULB — CoAP Simulator
#  Sends on/off state, brightness, color to CoAP server
#  Polls /home/light/command every 10s for commands
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import asyncio
import os
import json
import random
import aiocoap
import time
from datetime import datetime

#waiting for Service to run
time.sleep(10)

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
COAP_SERVER = os.environ.get('COAP_SERVER', '172.20.0.2')
DEVICE_ID   = os.environ.get('DEVICE_ID', 'lightbulb_01')
INTERVAL    = 30

URI_STATE   = f"coap://{COAP_SERVER}:5683/home/light"
URI_COMMAND = f"coap://{COAP_SERVER}:5683/home/light/command"

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "on":         True,
    "brightness": 80,
    "color_temp": "warm"
}

# ----------------------------------------------------------------
# COMMAND HANDLER
# ----------------------------------------------------------------
def handle_command(command):
    if command == "on":
        state["on"] = True
        print(f"[{DEVICE_ID}] Turned ON", flush=True)

    elif command == "off":
        state["on"] = False
        print(f"[{DEVICE_ID}] Turned OFF", flush=True)

    elif command.startswith("set_brightness:"):
        brightness        = int(command.split(":")[1])
        state["brightness"] = max(0, min(100, brightness))
        print(f"[{DEVICE_ID}] Brightness set to {state['brightness']}%", flush=True)

    elif command.startswith("set_color:"):
        color             = command.split(":")[1]
        state["color_temp"] = color
        print(f"[{DEVICE_ID}] Color temp set to {color}", flush=True)

    else:
        print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

# ----------------------------------------------------------------
# DATA SIMULATION
# ----------------------------------------------------------------
def get_light_data():
    # brightness fluctuates slightly when on
    if state["on"]:
        brightness = max(0, min(100, state["brightness"] + random.randint(-2, 2)))
    else:
        brightness = 0

    return {
        "device_id":  DEVICE_ID,
        "state":      "on" if state["on"] else "off",
        "brightness": brightness,
        "color_temp": state["color_temp"],
        "timestamp":  datetime.utcnow().isoformat()
    }

# ----------------------------------------------------------------
# PUBLISH LOOP
# ----------------------------------------------------------------
async def publish_loop(context):
    while True:
        try:
            payload  = json.dumps(get_light_data()).encode('utf-8')
            request  = aiocoap.Message(code=aiocoap.POST, uri=URI_STATE, payload=payload)
            response = await context.request(request).response
            print(f"[{DEVICE_ID}] Published — state:{'on' if state['on'] else 'off'} brightness:{state['brightness']}% response:{response.code}", flush=True)
        except Exception as e:
            print(f"[{DEVICE_ID}] Publish error: {e}", flush=True)

        await asyncio.sleep(INTERVAL)

# ----------------------------------------------------------------
# COMMAND POLL LOOP
# ----------------------------------------------------------------
async def command_loop(context):
    while True:
        try:
            request  = aiocoap.Message(code=aiocoap.GET, uri=URI_COMMAND)
            response = await context.request(request).response
            data     = json.loads(response.payload.decode('utf-8'))
            command  = data.get("command")

            if command:
                print(f"[{DEVICE_ID}] Command received: {command}", flush=True)
                handle_command(command)

        except Exception as e:
            print(f"[{DEVICE_ID}] Command poll error: {e}", flush=True)

        await asyncio.sleep(10)

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
async def main():
    print(f"[{DEVICE_ID}] Starting — CoAP server: {COAP_SERVER}", flush=True)
    await asyncio.sleep(5)

    context = await aiocoap.Context.create_client_context()

    await asyncio.gather(
        publish_loop(context),
        command_loop(context)
    )

if __name__ == '__main__':
    asyncio.run(main())