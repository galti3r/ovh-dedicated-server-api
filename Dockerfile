# syntax=docker/dockerfile:1.7

############################
# Builder (install deps)
############################
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (only if needed; kept minimal here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency file first (better layer caching)
COPY requirements.txt /app/requirements.txt

# Install deps into a custom prefix to copy later
RUN python -m pip install --upgrade pip && \
    python -m pip install --no-cache-dir --prefix=/install \
      -r /app/requirements.txt \
      gunicorn>=22,<23

############################
# Final image
############################
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ovh-dedicated-cli" \
      org.opencontainers.image.description="OVH Dedicated API — Flask web API + CLI" \
      org.opencontainers.image.source="https://github.com/${REPO:-owner/repo}" \
      org.opencontainers.image.licenses="MIT"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user
RUN useradd -m -u 10001 appuser

# Install runtime tools (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Bring in Python deps from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy app sources (do NOT copy .env; see .dockerignore)
COPY ovh_dedicated.py passenger_wsgi.py LICENSE README.md pyproject.toml /app/

# Expose app port
EXPOSE 8000

# Default: run the web API with gunicorn (override CMD for CLI usage)
USER appuser

# Healthcheck hits /healthz
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

# Access logs to stdout, error logs to stderr
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=4", "--timeout=30", "--access-logfile=-", "--error-logfile=-", "ovh_dedicated:app"]
