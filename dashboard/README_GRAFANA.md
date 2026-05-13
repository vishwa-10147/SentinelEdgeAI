# Grafana Integration (Starter)

This folder provides a small Grafana setup to visualize data from the Postgres DB used by SentinelEdgeAI.

Quick start (uses Docker Compose):

1. Set Postgres connection environment variables (point to your Postgres container):

```bash
export PG_HOST=sentinel-postgres
export PG_PORT=5432
export PG_DB=sentinel
export PG_USER=sentinel
export PG_PASSWORD=sentinel
```

2. Start Grafana:

```bash
cd deploy/grafana
docker compose up -d
```

3. Open Grafana at http://localhost:3000 (username `admin`, password `admin` by default).

Notes:
- The provided dashboard is a starter and queries the `alerts` and `flows` tables. You can extend it or create new dashboards in Grafana.
- If your Postgres runs on the Docker host (not a container named `sentinel-postgres`), set `PG_HOST` to the appropriate hostname reachable from the Grafana container (e.g., the container IP, `host.docker.internal` on some platforms, or run Grafana on the host).
