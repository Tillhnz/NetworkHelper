# Gebaut mit dem Projektordner als Kontext (siehe docker-compose.yml), damit die Agent-Dateien mit ins Image kommen
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    AGENT_DIR=/app/agent

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY agent ./agent

# Der Dienst läuft ohne Root-Rechte; /data hält die GeoIP-Datenbanken
RUN useradd --system --uid 10001 --no-create-home networkhelper \
    && mkdir -p /data && chown networkhelper /data
USER networkhelper

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
