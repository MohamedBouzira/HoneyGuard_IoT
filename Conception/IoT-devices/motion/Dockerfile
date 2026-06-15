# ================================================================
#  SIM-MOTION — Dockerfile
# ================================================================

FROM python:3.11-slim

RUN pip install aiocoap

COPY motion.py /app/motion.py

WORKDIR /app

CMD ["python3", "-u", "motion.py"]