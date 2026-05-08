# Backend image for SentinelEdgeAI
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system deps required by some Python extensions
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential gcc libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev libncursesw5-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app

# Expose port used by dashboard
EXPOSE 9000

CMD ["uvicorn", "dashboard.dashboard_api:app", "--host", "0.0.0.0", "--port", "9000"]
