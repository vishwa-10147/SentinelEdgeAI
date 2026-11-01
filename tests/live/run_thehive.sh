#!/usr/bin/env bash
# Live ticketing test: TheHive 5.4 (with Cassandra 4.1 and Elasticsearch 8.15) in Docker (not part of pytest).
#   bash tests/live/run_thehive.sh        # ~4 minutes on a Raspberry Pi 5
set -euo pipefail
cd "$(dirname "$0")/../.."
trap 'docker rm -f hive hive-es hive-cassandra >/dev/null 2>&1; docker network rm sentinel-hive >/dev/null 2>&1' EXIT
docker network create sentinel-hive >/dev/null 2>&1 || true
docker run -d --rm --name hive-cassandra --network sentinel-hive -e MAX_HEAP_SIZE=1G -e HEAP_NEWSIZE=200M \
  -e CASSANDRA_CLUSTER_NAME=TheHive cassandra:4.1 >/dev/null
docker run -d --rm --name hive-es --network sentinel-hive -e discovery.type=single-node -e xpack.security.enabled=false \
  -e ES_JAVA_OPTS="-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch:8.15.3 >/dev/null
until docker logs hive-cassandra 2>&1 | grep -q "Starting listening for CQL clients"; do sleep 5; done
docker run -d --rm --name hive --network sentinel-hive -p 127.0.0.1:9100:9000 -e JVM_OPTS="-Xms768m -Xmx768m" \
  strangebee/thehive:5.4 --secret "lab-secret-0123456789abcdef0123456789abcdef" --cql-hostnames hive-cassandra \
  --index-backend elasticsearch --es-hostnames hive-es >/dev/null
until curl -sf -u admin@thehive.local:secret localhost:9100/api/v1/user/current >/dev/null; do sleep 6; done
${PYTHON:-.venv/bin/python} tests/live/thehive_ticketing.py http://localhost:9100
