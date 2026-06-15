# ================================================================
#  SIM-DOORBELL — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install requests

COPY doorbell.py /app/doorbell.py

WORKDIR /app

CMD ["python3", "-u", "doorbell.py"]