# Grafana on PostgreSQL (optional)

For setups that store alerts and flows in PostgreSQL (`DATABASE_URL`), `deploy/grafana/` runs Grafana with a PostgreSQL datasource and a starter dashboard over the `alerts` and `flows` tables. For the operations dashboard built on Prometheus metrics, see `deploy/monitoring/README.md`.

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

3. Open Grafana at http://localhost:3000 and **change the default `admin`/`admin` password at first sign-in**.

Notes:
- The provided dashboard is a starter and queries the `alerts` and `flows` tables. You can extend it or create new dashboards in Grafana.
- If your Postgres runs on the Docker host (not a container named `sentinel-postgres`), set `PG_HOST` to the appropriate hostname reachable from the Grafana container (e.g., the container IP, `host.docker.internal` on some platforms, or run Grafana on the host).
