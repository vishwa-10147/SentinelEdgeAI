# SentinelEdgeAI API and console image: minimal, non-root.
#
#   docker build -t sentineledgeai .
#   docker run -p 9000:9000 -e SENTINEL_HOST=0.0.0.0 -v sentinel-data:/app/data sentineledgeai
#
# Builder stage installs the pinned dependencies (all available as wheels for
# amd64 and arm64, so no compilers are needed); the final stage has no build
# tools, no package manager cache and runs as an unprivileged user.

FROM python:3.11-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /venv \
    && /venv/bin/pip install --only-binary=:all: -r /tmp/requirements.txt

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/venv/bin:$PATH \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=9000
RUN groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel
COPY --from=builder /venv /venv
WORKDIR /app
COPY --chown=root:root . /app
RUN mkdir -p /app/data /app/logs && chown -R sentinel:sentinel /app/data /app/logs \
    && touch /app/alerts.json /app/firewall_rules.json /app/firewall_policy.json \
    && chown sentinel:sentinel /app/alerts.json /app/firewall_rules.json /app/firewall_policy.json
USER sentinel
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request,ssl,os; s='https' if os.environ.get('SENTINEL_TLS_CERT') else 'http'; urllib.request.urlopen(f'{s}://127.0.0.1:9000/api/auth/status', context=ssl._create_unverified_context(), timeout=4)" || exit 1
CMD ["python", "-m", "dashboard.serve"]
