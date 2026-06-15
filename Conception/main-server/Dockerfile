# ================================================================
#  MAIN SERVER — Dockerfile
#  Services: Cowrie + Mosquitto + CoAP + HTTP + IoT Platform
#  Base: Ubuntu 22.04
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

FROM ubuntu:22.04

# ----------------------------------------------------------------
# 1. ENVIRONMENT — avoid interactive prompts during apt installs
# ----------------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive

# ----------------------------------------------------------------
# 2. SYSTEM DEPENDENCIES
# ----------------------------------------------------------------
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    nano \
    net-tools \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    mosquitto \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------
# 3. PYTHON LIBRARIES
#    — CoAP server, HTTP server, IoT platform
# ----------------------------------------------------------------
RUN pip3 install \
    aiocoap \
    flask \
    flask-socketio \
    paho-mqtt \
    requests \
    eventlet

# ----------------------------------------------------------------
# 4. COPY ALL CONFIG FILES
# ----------------------------------------------------------------
COPY configs/ /tmp/configs/

# verify all required files are present
RUN test -s /tmp/configs/cowrie.cfg          || (echo "ERROR: cowrie.cfg missing!"          && exit 1)
RUN test -s /tmp/configs/mosquitto.conf      || (echo "ERROR: mosquitto.conf missing!"      && exit 1)
RUN test -s /tmp/configs/coap_server.py      || (echo "ERROR: coap_server.py missing!"      && exit 1)
RUN test -s /tmp/configs/http_server.py      || (echo "ERROR: http_server.py missing!"      && exit 1)
# tshark_capture.sh is no longer used — tshark_to_json.py is the standalone daemon
RUN test -s /tmp/configs/tshark_to_json.py   || (echo "ERROR: tshark_to_json.py missing!"   && exit 1)
RUN test -s /tmp/configs/IoT_platform/app.py || (echo "ERROR: IoT_platform/app.py missing!" && exit 1)

# copy server scripts
RUN cp /tmp/configs/coap_server.py      /opt/coap_server.py
RUN cp /tmp/configs/http_server.py      /opt/http_server.py
RUN cp /tmp/configs/mqtt_logger.py      /opt/mqtt_logger.py
RUN cp /tmp/configs/tshark_to_json.py   /opt/tshark_to_json.py

# allow tshark to capture without root
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/tshark || true

# copy IoT platform
RUN cp -r /tmp/configs/IoT_platform /opt/IoT_platform

# ----------------------------------------------------------------
# 5. COWRIE — SSH/Telnet honeypot
# ----------------------------------------------------------------
RUN useradd -m -s /bin/bash cowrie

RUN git clone https://github.com/cowrie/cowrie.git /home/cowrie/cowrie

RUN cd /home/cowrie/cowrie && \
    python3 -m venv cowrie-env && \
    /home/cowrie/cowrie/cowrie-env/bin/pip install --upgrade pip && \
    /home/cowrie/cowrie/cowrie-env/bin/pip install -r requirements.txt && \
    /home/cowrie/cowrie/cowrie-env/bin/pip install -e .

RUN cp /tmp/configs/cowrie.cfg /home/cowrie/cowrie/etc/cowrie.cfg
RUN chown -R cowrie:cowrie /home/cowrie/cowrie

# ----------------------------------------------------------------
# 6. MOSQUITTO — MQTT broker
# ----------------------------------------------------------------
RUN cp /tmp/configs/mosquitto.conf /etc/mosquitto/mosquitto_custom.conf

RUN mkdir -p /var/lib/mosquitto && \
    chown mosquitto:mosquitto /var/lib/mosquitto

# ----------------------------------------------------------------
# 7. LOG DIRECTORIES
# ----------------------------------------------------------------
RUN mkdir -p /var/log/cowrie \
             /var/log/coap \
             /var/log/http \
             /var/log/mqtt \
             /var/log/iot_platform \
             /var/log/tshark \
    && chown -R cowrie:cowrie /var/log/cowrie \
    && chmod 755 /var/log/cowrie

# ----------------------------------------------------------------
# 8. LOGROTATE — prevent null bytes, safe log rotation
# ----------------------------------------------------------------
RUN apt-get update && apt-get install -y logrotate && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN printf '/var/log/mqtt/mqtt.json\n/var/log/http/http.json\n/var/log/coap/coap.json\n/var/log/tshark/packets.json\n/var/log/cowrie/cowrie.json\n/var/log/iot_platform/platform.json {\n    daily\n    rotate 7\n    compress\n    missingok\n    notifempty\n    postrotate\n        supervisorctl restart mqtt-logger http-server coap-server iot_platform tshark-capture 2>/dev/null || true\n    endscript\n}\n' > /etc/logrotate.d/honeypot && chmod 644 /etc/logrotate.d/honeypot

# ----------------------------------------------------------------
# 9. SUPERVISOR CONFIG
# ----------------------------------------------------------------
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY configs/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ----------------------------------------------------------------
# 9. PORTS
# ----------------------------------------------------------------
EXPOSE 2222/tcp
EXPOSE 2223/tcp
EXPOSE 1883/tcp
EXPOSE 5683/udp
EXPOSE 8080/tcp
EXPOSE 80/tcp

# ----------------------------------------------------------------
# 10. ENTRYPOINT
# ----------------------------------------------------------------
CMD ["/entrypoint.sh"]