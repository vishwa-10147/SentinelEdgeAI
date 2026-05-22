import sqlite3
import threading
import time
from typing import Optional


class SQLiteStorage:
    def __init__(self, path: str = "data/sentinel.db"):
        self.path = path
        self._lock = threading.Lock()
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self):
        with self._lock:
            if self.conn:
                return
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                score REAL,
                confidence REAL,
                details TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                bytes INTEGER,
                packets INTEGER,
                last_ts INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS firewall_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                action TEXT,
                ip TEXT,
                rule_id TEXT,
                details TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS live_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                type TEXT,
                payload TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE,
                last_seen INTEGER,
                payload TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS live_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                payload TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                device_id TEXT,
                risk INTEGER,
                payload TEXT
            )
            """
        )
        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_srcdst ON flows(src_ip,dst_ip)")
        self.conn.commit()

    # Allowed tables for cleanup_retention to prevent SQL injection
    _ALLOWED_TABLES = {
        "alerts",
        "flows",
        "firewall_actions",
        "live_events",
        "device_profiles",
        "live_stats",
        "risk_timeline",
    }

    def insert_alert(self, ts: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, score: float, confidence: float, details: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO alerts(ts,src_ip,dst_ip,src_port,dst_port,proto,score,confidence,details) VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, src_ip, dst_ip, src_port, dst_port, proto, score, confidence, details),
        )
        self.conn.commit()

    def insert_flow(self, ts: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, bytes_count: int, packets: int, last_ts: int):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO flows(ts,src_ip,dst_ip,src_port,dst_port,proto,bytes,packets,last_ts) VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, src_ip, dst_ip, src_port, dst_port, proto, bytes_count, packets, last_ts),
        )
        self.conn.commit()

    def insert_firewall_action(self, ts: int, action: str, ip: str, rule_id: str, details: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO firewall_actions(ts,action,ip,rule_id,details) VALUES (?,?,?,?,?)",
            (ts, action, ip, rule_id, details),
        )
        self.conn.commit()

    def insert_live_event(self, ts: int, type: str, payload_json: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO live_events(ts,type,payload) VALUES (?,?,?)",
            (ts, type, payload_json),
        )
        self.conn.commit()

    def upsert_device_profile(self, device_id: str, last_seen: int, payload_json: str):
        self.connect()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO device_profiles(device_id,last_seen,payload) VALUES (?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen, payload=excluded.payload",
            (device_id, last_seen, payload_json),
        )
        self.conn.commit()

    def get_live_events(self, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT ts,payload FROM live_events ORDER BY ts ASC LIMIT ?", (limit,))
        rows = cur.fetchall()
        return [(r[0], r[1]) for r in rows]

    def get_device_profiles(self):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT device_id, payload FROM device_profiles")
        rows = cur.fetchall()
        out = {}
        for device_id, payload in rows:
            out[device_id] = payload
        return out

    def get_flows(self, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        cur.execute("SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, last_ts FROM flows ORDER BY ts DESC LIMIT ?", (limit,))
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
        # keep a single most recent snapshot; insert with ts
        cur.execute("INSERT INTO live_stats(ts,payload) VALUES (?,?)", (ts, payload_json))
        # trim to last 10 snapshots to limit growth
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
        cur.execute("INSERT INTO risk_timeline(ts,device_id,risk,payload) VALUES (?,?,?,?)", (ts, device_id, risk, payload_json))
        # trim to last 500 per device to limit growth
        cur.execute("DELETE FROM risk_timeline WHERE id NOT IN (SELECT id FROM risk_timeline WHERE device_id=? ORDER BY ts DESC LIMIT 500)", (device_id,))
        self.conn.commit()

    def get_risk_timeline(self, device_id: str = None, limit: int = 500):
        self.connect()
        cur = self.conn.cursor()
        if device_id:
            cur.execute("SELECT ts,risk,payload FROM risk_timeline WHERE device_id=? ORDER BY ts DESC LIMIT ?", (device_id, limit))
        else:
            cur.execute("SELECT ts,device_id,risk,payload FROM risk_timeline ORDER BY ts DESC LIMIT ?", (limit,))
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
        cur.execute("SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, score, confidence, details FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
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
        # Only allow a fixed set of table names to avoid SQL injection
        if table not in self._ALLOWED_TABLES:
            raise ValueError(f"invalid table name: {table}")
        # table is validated against a whitelist above; suppress Bandit B608
        cur.execute("DELETE FROM %s WHERE ts < ?" % table, (cutoff,))  # nosec
        self.conn.commit()

    def vacuum(self):
        """Run VACUUM to compact the SQLite database."""
        self.connect()
        cur = self.conn.cursor()
        cur.execute("VACUUM")
        self.conn.commit()
