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
        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_srcdst ON flows(src_ip,dst_ip)")
        self.conn.commit()

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

    def cleanup_retention(self, table: str, max_age_seconds: int):
        self.connect()
        cutoff = int(time.time()) - max_age_seconds
        cur = self.conn.cursor()
        cur.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
        self.conn.commit()
