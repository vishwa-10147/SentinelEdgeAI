#!/usr/bin/env python3
"""Initialize SQLite DB for SentinelEdgeAI"""
import argparse
from core.storage_sqlite import SQLiteStorage


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="data/sentinel.db")
    args = p.parse_args()

    storage = SQLiteStorage(args.db)
    storage.create_tables()
    print(f"Initialized DB at {args.db}")


if __name__ == "__main__":
    main()
