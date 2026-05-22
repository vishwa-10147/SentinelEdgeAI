import threading
import time
import os
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values
from typing import Optional


class PostgresStorage:
    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.environ.get("DATABASE_URL")
        if not self.dsn:
            raise ValueError("DATABASE_URL must be set for PostgresStorage")
        self._lock = threading.Lock()
        self.conn: Optional[psycopg2.extensions.connection] = None

    def connect(self):
        with self._lock:
            if self.conn:
                return
            self.conn = psycopg2.connect(self.dsn)
            self.conn.autocommit = False

    def close(self):
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None

    def create_tables(self):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                score DOUBLE PRECISION,
                confidence DOUBLE PRECISION,
                details TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS flows (
                id SERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                bytes BIGINT,
                packets BIGINT,
                last_ts BIGINT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS firewall_actions (
                id SERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                action TEXT,
                ip TEXT,
                rule_id TEXT,
                details TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS live_events (
                id SERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                type TEXT,
                payload TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_profiles (
                id SERIAL PRIMARY KEY,
                device_id TEXT UNIQUE,
                last_seen BIGINT,
                payload TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS live_stats (
                id SERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                payload TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_timeline (
                id SERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                device_id TEXT,
                risk INTEGER,
                payload TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_srcdst ON flows(src_ip,dst_ip);")
        self.conn.commit()

    def insert_alert(self, ts: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, score: float, confidence: float, details: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO alerts(ts,src_ip,dst_ip,src_port,dst_port,proto,score,confidence,details) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (ts, src_ip, dst_ip, src_port, dst_port, proto, score, confidence, details),
        )
        self.conn.commit()

    def insert_flow(self, ts: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, bytes_count: int, packets: int, last_ts: int):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO flows(ts,src_ip,dst_ip,src_port,dst_port,proto,bytes,packets,last_ts) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (ts, src_ip, dst_ip, src_port, dst_port, proto, bytes_count, packets, last_ts),
        )
        self.conn.commit()

    def insert_firewall_action(self, ts: int, action: str, ip: str, rule_id: str, details: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO firewall_actions(ts,action,ip,rule_id,details) VALUES (%s,%s,%s,%s,%s)",
            (ts, action, ip, rule_id, details),
        )
        self.conn.commit()

    def insert_live_event(self, ts: int, type: str, payload_json: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO live_events(ts,type,payload) VALUES (%s,%s,%s)",
            (ts, type, payload_json),
        )
        self.conn.commit()

    def upsert_device_profile(self, device_id: str, last_seen: int, payload_json: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO device_profiles(device_id,last_seen,payload) VALUES (%s,%s,%s) ON CONFLICT (device_id) DO UPDATE SET last_seen=EXCLUDED.last_seen, payload=EXCLUDED.payload",
            (device_id, last_seen, payload_json),
        )
        self.conn.commit()

    def get_live_events(self, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT ts,payload FROM live_events ORDER BY ts ASC LIMIT %s", (limit,))
        rows = cur.fetchall()
        return [(r[0], r[1]) for r in rows]

    def get_device_profiles(self):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT device_id, payload FROM device_profiles")
        rows = cur.fetchall()
        out = {r[0]: r[1] for r in rows}
        return out

    def get_flows(self, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, last_ts FROM flows ORDER BY ts DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "timestamp": r[0],
                "src_ip": r[1],
                "dst_ip": r[2],
                "src_port": r[3],
                "dst_port": r[4],
                "protocol": r[5],
                "bytes": r[6],
                "packets": r[7],
                "last_ts": r[8],
            })
        return out

    def upsert_live_stats(self, ts: int, payload_json: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("INSERT INTO live_stats(ts,payload) VALUES (%s,%s)", (ts, payload_json))
        cur.execute("DELETE FROM live_stats WHERE id NOT IN (SELECT id FROM live_stats ORDER BY ts DESC LIMIT 10)")
        self.conn.commit()

    def get_live_stats(self):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT payload FROM live_stats ORDER BY ts DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else None

    def insert_risk_timeline(self, ts: int, device_id: str, risk: int, payload_json: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("INSERT INTO risk_timeline(ts,device_id,risk,payload) VALUES (%s,%s,%s,%s)", (ts, device_id, risk, payload_json))
        cur.execute("DELETE FROM risk_timeline WHERE id NOT IN (SELECT id FROM risk_timeline WHERE device_id=%s ORDER BY ts DESC LIMIT 500)", (device_id,))
        self.conn.commit()

    def get_risk_timeline(self, device_id: str = None, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        if device_id:
            cur.execute("SELECT ts,risk,payload FROM risk_timeline WHERE device_id=%s ORDER BY ts DESC LIMIT %s", (device_id, limit))
        else:
            cur.execute("SELECT ts,device_id,risk,payload FROM risk_timeline ORDER BY ts DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            if device_id:
                out.append({"timestamp": r[0], "risk": r[1], "payload": r[2]})
            else:
                out.append({"timestamp": r[0], "device_id": r[1], "risk": r[2], "payload": r[3]})
        return out

    def get_alerts(self, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, score, confidence, details FROM alerts ORDER BY ts DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "timestamp": r[0],
                "src_ip": r[1],
                "dst_ip": r[2],
                "src_port": r[3],
                "dst_port": r[4],
                "protocol": r[5],
                "score": r[6],
                "confidence": r[7],
                "details": r[8],
            })
        return out

    def cleanup_retention(self, table: str, max_age_seconds: int):
        self.connect()
        cutoff = int(time.time()) - max_age_seconds
        cur = self.conn.cursor()
        # Protect against SQL injection by using Identifier for table names
        # and only formatting the identifier, leaving values parameterized.
        cur.execute(sql.SQL("DELETE FROM {} WHERE ts < %s").format(sql.Identifier(table)), (cutoff,))
        self.conn.commit()

    def vacuum(self):
        # Postgres: run VACUUM
        self.connect()
        cur = self.conn.cursor()
        cur.execute("VACUUM")
        self.conn.commit()
