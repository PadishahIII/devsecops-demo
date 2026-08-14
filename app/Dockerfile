# syntax=docker/dockerfile:1
# Base image is pinned by digest — never a moving tag (design decision #3).
FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65

LABEL org.opencontainers.image.source="https://github.com/PadishahIII/devsecops-demo"
LABEL org.opencontainers.image.description="devsecops-demo notes app"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install deps first for layer caching, then drop privileges.
COPY --chmod=0644 requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system app \
    && adduser --system --ingroup app --home /app app

COPY --chmod=0644 app.py config.py db.py ./
COPY --chmod=u=rwX,go=rX templates ./templates

USER app
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "2", "--log-level", "warning", "app:app"]
