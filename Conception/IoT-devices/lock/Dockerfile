# ================================================================
#  SIM-LOCK — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install paho-mqtt

COPY lock.py /app/lock.py

WORKDIR /app

CMD ["python3", "-u", "lock.py"]