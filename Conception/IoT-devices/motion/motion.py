# ================================================================
#  SIM-MOTION — CoAP Simulator
#  Sends motion detection events to CoAP server
#  Polls /home/motion/command every 10s for commands
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import asyncio
import os
import json
import random
import aiocoap
from datetime import datetime
import time

#waiting for Service to run
time.sleep(10)

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
COAP_SERVER = os.environ.get('COAP_SERVER', '172.20.0.2')
DEVICE_ID   = os.environ.get('DEVICE_ID', 'motion_01')
INTERVAL    = 20

URI_STATE   = f"coap://{COAP_SERVER}:5683/home/motion"
URI_COMMAND = f"coap://{COAP_SERVER}:5683/home/motion/command"

ZONES = ["living_room", "hallway", "garden", "garage"]

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "enabled":     True,
    "sensitivity": "medium"
}

# ----------------------------------------------------------------
# DATA SIMULATION
# ----------------------------------------------------------------
def get_motion_data():
    # if disabled — always report no motion
    detected = False
    if state["enabled"]:
        detected = random.choices([False, True], weights=[70, 30])[0]

    return {
        "device_id": DEVICE_ID,
        "motion":    detected,
        "zone":      random.choice(ZONES),
        "enabled":   state["enabled"],
        "timestamp": datetime.utcnow().isoformat()
    }

# ----------------------------------------------------------------
# COMMAND HANDLER
# ----------------------------------------------------------------
def handle_command(command):
    if command == "enable":
        state["enabled"] = True
        print(f"[{DEVICE_ID}] Motion detection enabled", flush=True)

    elif command == "disable":
        state["enabled"] = False
        print(f"[{DEVICE_ID}] Motion detection disabled", flush=True)

    else:
        print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

# ----------------------------------------------------------------
# PUBLISH LOOP — sends state every INTERVAL seconds
# ----------------------------------------------------------------
async def publish_loop(context):
    while True:
        try:
            payload = json.dumps(get_motion_data()).encode('utf-8')
            request = aiocoap.Message(code=aiocoap.POST, uri=URI_STATE, payload=payload)
            response = await context.request(request).response
            print(f"[{DEVICE_ID}] Published — enabled:{state['enabled']} response:{response.code}", flush=True)
        except Exception as e:
            print(f"[{DEVICE_ID}] Publish error: {e}", flush=True)

        await asyncio.sleep(INTERVAL)

# ----------------------------------------------------------------
# COMMAND POLL LOOP — polls for commands every 10 seconds
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
    await asyncio.sleep(5)   # wait for CoAP server to be ready

    context = await aiocoap.Context.create_client_context()

    # run both loops concurrently
    await asyncio.gather(
        publish_loop(context),
        command_loop(context)
    )

if __name__ == '__main__':
    asyncio.run(main())