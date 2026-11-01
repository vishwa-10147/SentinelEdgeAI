#!/usr/bin/env bash
# Live SIEM test: Elasticsearch 8 + Filebeat 8 (deploy/elastic/filebeat.yml) in Docker (not part of pytest).
#   bash tests/live/run_elastic.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
V=8.15.3; D=$(mktemp -d); chmod 777 "$D"
trap 'docker rm -f sentinel-es sentinel-fb >/dev/null 2>&1; rm -rf "$D"' EXIT
docker network create sentinel-elastic >/dev/null 2>&1 || true
docker run -d --rm --name sentinel-es --network sentinel-elastic -p 127.0.0.1:9200:9200 -e discovery.type=single-node \
  -e xpack.security.enabled=false -e ES_JAVA_OPTS="-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch:$V >/dev/null
until curl -sf localhost:9200/_cluster/health >/dev/null; do sleep 3; done
touch "$D/alerts.jsonl"; chmod 666 "$D/alerts.jsonl"
sed "s#/var/lib/sentinel/logs/alerts.jsonl#/data/alerts.jsonl#" deploy/elastic/filebeat.yml > "$D/filebeat.yml"; chmod 644 "$D/filebeat.yml"
docker run -d --rm --name sentinel-fb --network sentinel-elastic -p 127.0.0.1:5514:5514 -v "$D":/data \
  -v "$D/filebeat.yml":/usr/share/filebeat/filebeat.yml:ro -e ES_HOST=http://sentinel-es:9200 \
  docker.elastic.co/beats/filebeat:$V filebeat -e --strict.perms=false >/dev/null
# Docker's port proxy accepts connections before Filebeat listens: wait for Filebeat's own log line
until docker logs sentinel-fb 2>&1 | grep -q "starting tcp socket input"; do sleep 2; done; sleep 3
${PYTHON:-.venv/bin/python} tests/live/elastic_ship.py http://localhost:9200 "$D/alerts.jsonl"
