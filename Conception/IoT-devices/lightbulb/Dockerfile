# ================================================================
#  SIM-LIGHTBULB — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install aiocoap

COPY lightbulb.py /app/lightbulb.py

WORKDIR /app

CMD ["python3", "-u", "lightbulb.py"]