from core.storage_sqlite import SQLiteStorage


def test_connect_creates_missing_parent_directory(tmp_path):
    db_path = tmp_path / "fresh" / "nested" / "sentinel.db"
    storage = SQLiteStorage(str(db_path))
    storage.create_tables()
    storage.close()
    assert db_path.exists()


def test_connect_supports_in_memory_database():
    storage = SQLiteStorage(":memory:")
    storage.create_tables()
    storage.close()
