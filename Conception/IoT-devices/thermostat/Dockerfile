# ================================================================
#  SIM-THERMOSTAT — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install paho-mqtt

COPY thermostat.py /app/thermostat.py

WORKDIR /app

CMD ["python3", "-u", "thermostat.py"]