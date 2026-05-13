#!/usr/bin/env python3
"""Initialize SQLite DB for SentinelEdgeAI"""
import argparse
from core.storage import get_storage


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="data/sentinel.db")
    args = p.parse_args()

    storage = get_storage(args.db)
    storage.create_tables()
    print(f"Initialized DB at {args.db}")


if __name__ == "__main__":
    main()
