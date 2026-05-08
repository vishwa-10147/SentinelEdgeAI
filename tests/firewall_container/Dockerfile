FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY core /app/core
COPY tests/firewall_container/run_firewall_backend.py /app/run_firewall_backend.py

ENV PYTHONPATH=/app
CMD ["python", "/app/run_firewall_backend.py"]
