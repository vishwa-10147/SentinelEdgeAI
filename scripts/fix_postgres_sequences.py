#!/usr/bin/env python3
"""Advance Postgres SERIAL sequences to match max(id) per table.

Usage: DATABASE_URL=postgresql://user:pw@host:5432/db python3 scripts/fix_postgres_sequences.py
"""
import os
import sys
import psycopg2
from psycopg2 import sql

dsn = os.environ.get("DATABASE_URL")
if not dsn:
    print("Set DATABASE_URL environment variable to target Postgres DSN")
    sys.exit(2)

TABLES = [
    "alerts",
    "flows",
    "firewall_actions",
    "live_events",
    "device_profiles",
    "live_stats",
    "risk_timeline",
]


def main():
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    for t in TABLES:
        print(f"Processing table {t}...")
        # find the sequence associated with t.id
        cur.execute("SELECT pg_get_serial_sequence(%s,%s)", (t, 'id'))
        seq = cur.fetchone()[0]
        if not seq:
            print(f"  No serial sequence found for {t}. Skipping.")
            continue
        # Use sql.Identifier to safely format table identifiers
        cur.execute(sql.SQL("SELECT COALESCE(MAX(id),0) FROM {}").format(sql.Identifier(t)))
        maxid = cur.fetchone()[0]
        # Ensure we set at least 1 to avoid out-of-range for sequences starting at 1
        set_to = max(1, int(maxid))
        print(f"  sequence={seq}, max(id)={maxid}, setting setval to {set_to}")
        cur.execute("SELECT setval(%s, %s, true)", (seq, set_to))
        conn.commit()
    cur.close()
    conn.close()
    print("All done.")


if __name__ == "__main__":
    main()
