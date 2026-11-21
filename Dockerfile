FROM python:3.11-slim

ARG APP_VERSION=3.9.1
LABEL org.opencontainers.image.title="Phishing Detection Engine" \
      org.opencontainers.image.version=$APP_VERSION \
      org.opencontainers.image.source="https://github.com/VibeATSCoder/phishing-detection-engine"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/tmp/detector-home

WORKDIR /app
COPY pyproject.toml requirements.txt requirements-browser.txt ./
# Playwright's bundled Node runtime needs libatomic before it can install Chromium.
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --upgrade pip && \
    pip install --requirement requirements-browser.txt && \
    playwright install --with-deps chromium && \
    addgroup --system detector && \
    adduser --system --ingroup detector --home /home/detector detector

COPY src ./src
RUN pip install --no-deps .
COPY artifacts ./artifacts
RUN mkdir -p /app/var/results && \
    chown -R detector:detector /app/var && \
    chmod -R a+rX /ms-playwright

USER detector
EXPOSE 8088
CMD ["uvicorn", "persianphish_detector.api:app", "--host", "0.0.0.0", "--port", "8088", "--workers", "1", "--timeout-keep-alive", "5", "--limit-concurrency", "8", "--backlog", "32"]
