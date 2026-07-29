# CloudChain backend.
FROM python:3.12-slim AS base

# Fail fast and log immediately: buffered output in a container means a crash
# loop shows you nothing.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies are copied and installed before the source so a code change
# doesn't invalidate the pip layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests

# Scan snapshots live on a volume; without one, drift detection resets every
# time the container restarts, which quietly makes the feature useless.
ENV CLOUDCHAIN_DB_PATH=/data/cloudchain.db
RUN mkdir -p /data

# Run as a non-root user. This container talks to AWS with read-only
# credentials and has no reason to be able to write to its own image.
RUN useradd --create-home --uid 10001 cloudchain \
    && chown -R cloudchain:cloudchain /data /app
USER cloudchain

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
