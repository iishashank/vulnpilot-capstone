from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from pathlib import Path

# Ops DB stores scan runs, logs, assets, findings (separate from vuln_lookup.db)
_db_path = Path(__file__).resolve().parent.parent / "datasets" / "ops.db"
DATABASE_URL = f"sqlite:///{_db_path}"

def _sqlite_engine(url: str):
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA busy_timeout = 5000")
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = NORMAL")
        cursor.close()

    return engine


engine = _sqlite_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Vulnerability lookup DB (read-only, built by setup_datasets.py)
_vuln_db_path = Path(__file__).resolve().parent.parent / "datasets" / "vuln_lookup.db"
VULN_DB_URL = f"sqlite:///{_vuln_db_path}"
vuln_engine = _sqlite_engine(VULN_DB_URL)
VulnSessionLocal = sessionmaker(bind=vuln_engine, autocommit=False, autoflush=False)
