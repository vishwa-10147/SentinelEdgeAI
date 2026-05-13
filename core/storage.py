import os
from typing import Optional

DB_URL_ENV = "DATABASE_URL"


def get_storage(sqlite_path: str = "data/sentinel.db"):
    """Return a storage instance. If DATABASE_URL is set, return PostgresStorage,
    otherwise return SQLiteStorage pointing at `sqlite_path`."""
    if os.environ.get(DB_URL_ENV):
        from .storage_postgres import PostgresStorage

        return PostgresStorage(os.environ.get(DB_URL_ENV))
    else:
        from .storage_sqlite import SQLiteStorage

        return SQLiteStorage(sqlite_path)
