# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

# Security: non-root user
RUN groupadd -r passguard && useradd -r -g passguard passguard

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Security: no setuid binaries, drop capabilities via docker-compose
RUN chown -R passguard:passguard /app

USER passguard

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
