# PhishGuard Backend — Dockerfile
# Multi-stage build: builder → runtime
# Final image is ~120MB (python:3.12-slim base)
#
# Author: Akshay | https://akshay.fruvvi.com

# ── Stage 1: Build dependencies ───────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into a dedicated layer for caching
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime image ────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN useradd -m -u 1000 -s /bin/bash phishguard

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ app/

# Switch to non-root user
USER phishguard

# Health check — Docker will mark container unhealthy if this fails
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
