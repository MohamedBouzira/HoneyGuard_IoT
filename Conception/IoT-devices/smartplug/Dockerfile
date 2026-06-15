# ================================================================
#  SIM-PLUG — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install paho-mqtt

COPY plug.py /app/plug.py

WORKDIR /app

CMD ["python3", "-u", "plug.py"]