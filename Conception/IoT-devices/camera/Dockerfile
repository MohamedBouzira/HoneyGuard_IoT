# ================================================================
#  SIM-CAMERA — Dockerfile
#  HTTP events + RTSP stream via mediamtx + ffmpeg
# ================================================================

FROM python:3.11-slim

# ----------------------------------------------------------------
# SYSTEM DEPS — ffmpeg
# ----------------------------------------------------------------
RUN apt-get update && apt-get install -y \
    ffmpeg \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------
# PYTHON DEPS
# ----------------------------------------------------------------
RUN pip install requests

# ----------------------------------------------------------------
# MEDIAMTX — lightweight RTSP server
# ----------------------------------------------------------------
RUN wget -q https://github.com/bluenviron/mediamtx/releases/download/v1.9.0/mediamtx_v1.9.0_linux_amd64.tar.gz \
    -O /tmp/mediamtx.tar.gz && \
    mkdir -p /opt/mediamtx && \
    tar -xzf /tmp/mediamtx.tar.gz -C /opt/mediamtx && \
    rm /tmp/mediamtx.tar.gz

# ----------------------------------------------------------------
# COPY FILES
# ----------------------------------------------------------------
COPY camera.py        /app/camera.py
COPY rtsp_server.sh   /app/rtsp_server.sh
COPY mediamtx.yml     /opt/mediamtx/mediamtx.yml
COPY footage.mp4      /app/footage.mp4

RUN chmod +x /app/rtsp_server.sh

WORKDIR /app

# ----------------------------------------------------------------
# PORTS
# ----------------------------------------------------------------
EXPOSE 8554/tcp

# ----------------------------------------------------------------
# ENTRYPOINT — start RTSP server + camera script
# ----------------------------------------------------------------
CMD bash -c "/app/rtsp_server.sh & python3 -u /app/camera.py"