# ================================================================
#  SIM-ALARM — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install paho-mqtt

COPY alarm.py /app/alarm.py

WORKDIR /app

CMD ["python3", "-u", "alarm.py"]