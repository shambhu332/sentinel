FROM python:3.12-slim

# System deps: Java for JADX/apktool, ADB, semgrep, node for frida-agent
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    android-sdk-platform-tools \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.4

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml poetry.lock* ./

# Install Python dependencies (no dev extras)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --without dev

# Copy project source
COPY sentinel/ ./sentinel/
COPY migrations/ ./migrations/
COPY scripts/ ./scripts/
COPY rules/ ./rules/ 2>/dev/null || true
COPY frida_agent/_agent.js ./frida_agent/_agent.js 2>/dev/null || true

# Create workspace directory
RUN mkdir -p /workspace

ENV SENTINEL_WORKSPACE=/workspace
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["uvicorn", "sentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
