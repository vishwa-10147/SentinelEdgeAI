#!/usr/bin/env python3
"""Simple migration tool: copy tables from SQLite to Postgres using psycopg2.

Run: DATABASE_URL=postgresql://user:pw@host:5432/sentinel python3 scripts/migrate_sqlite_to_postgres.py
"""
import sqlite3
import os
import sys
from typing import List

dsn = os.environ.get("DATABASE_URL")
if not dsn:
    print("Set DATABASE_URL environment variable to target Postgres DSN")
    sys.exit(2)

import psycopg2
from psycopg2 import sql, extras

SRC = "data/sentinel.db"

TABLES = [
    "alerts",
    "flows",
    "firewall_actions",
    "live_events",
    "device_profiles",
    "live_stats",
    "risk_timeline",
]


def copy_table(conn_src: sqlite3.Connection, conn_dst: psycopg2.extensions.connection, table: str):
    cur_src = conn_src.cursor()
    cur_dst = conn_dst.cursor()
    # Only allow known table names to avoid SQL injection
    if table not in TABLES:
        raise ValueError("invalid table")
    # For sqlite3 we validate table against whitelist above; suppress Bandit B608
    cur_src.execute("SELECT * FROM %s" % table)  # nosec B608
    rows = cur_src.fetchall()
    if not rows:
        print(f"{table}: no rows, skipping")
        return
    # get column count
    colcount = len(rows[0])
    placeholders = ",".join(["%s"] * colcount)
    # Use psycopg2.sql to safely format the table identifier for Postgres
    insert_sql = sql.SQL("INSERT INTO {} VALUES %s").format(sql.Identifier(table))
    print(f"Inserting {len(rows)} rows into {table}...")
    psy_rows = [tuple(r) for r in rows]
    try:
        extras.execute_values(cur_dst, insert_sql, psy_rows)
    except Exception:
        # fallback to executemany
        # executemany expects a plain string; use formatted SQL with Identifier
        cur_dst.executemany(insert_sql.as_string(conn_dst), psy_rows)
    conn_dst.commit()


def main():
    if not os.path.exists(SRC):
        print("Source SQLite DB not found at", SRC)
        sys.exit(1)
    conn_src = sqlite3.connect(SRC)
    conn_dst = psycopg2.connect(dsn)
    # ensure tables exist by importing storage_postgres and calling create_tables
    from core.storage_postgres import PostgresStorage

    s = PostgresStorage(dsn)
    s.create_tables()

    for t in TABLES:
        copy_table(conn_src, conn_dst, t)

    conn_src.close()
    conn_dst.close()
    print("Migration complete")


if __name__ == "__main__":
    main()
