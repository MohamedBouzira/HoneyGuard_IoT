#!/bin/bash
# ================================================================
#  RTSP SERVER — mediamtx + ffmpeg loop
#  Streams footage.mp4 on repeat via RTSP
# ================================================================

# start mediamtx in background
/opt/mediamtx/mediamtx /opt/mediamtx/mediamtx.yml &

# wait for mediamtx to be ready
sleep 5

echo "[RTSP] Starting stream loop from footage.mp4..."

# loop footage.mp4 forever and push to mediamtx via RTSP
while true; do
    ffmpeg -re \
           -stream_loop -1 \
           -i /app/footage.mp4 \
           -c:v libx264 \
           -preset ultrafast \
           -tune zerolatency \
           -b:v 1500k \
           -c:a aac \
           -f rtsp \
           rtsp://localhost:8554/live \
           -loglevel warning
    echo "[RTSP] Stream ended — restarting..."
    sleep 2
done