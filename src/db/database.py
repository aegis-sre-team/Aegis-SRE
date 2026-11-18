import logging
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

logger = logging.getLogger("aegis-db")

DB_DIR = os.getenv("AEGIS_DB_DIR", "logs")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "aegis_sre.db")
# Empty string from optional K8s secret must fall back to SQLite on the data volume.
def normalize_database_url(url: str) -> str:
    """Pin a bare postgres URL to psycopg2 (the driver in requirements.txt).

    Newer SQLAlchemy defaults `postgresql://` to psycopg v3, which is not installed, so the brain
    crash-looped on import. An explicit `postgresql+<driver>://` is left alone.
    """
    for bare in ("postgresql://", "postgres://"):
        if url.startswith(bare):
            return "postgresql+psycopg2://" + url[len(bare):]
    return url


DATABASE_URL = normalize_database_url((os.getenv("DATABASE_URL") or "").strip()) or f"sqlite:///{DB_PATH}"

_is_sqlite = DATABASE_URL.startswith("sqlite")
_engine_kwargs = {
    "pool_pre_ping": True,
}
if _is_sqlite:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def configure_database(database_url: str):
    """Rebind the global engine/session (used by tests and alternate deployments)."""
    global engine, SessionLocal, DATABASE_URL, _is_sqlite
    try:
        engine.dispose()
    except Exception:
        pass
    DATABASE_URL = normalize_database_url(database_url)
    _is_sqlite = DATABASE_URL.startswith("sqlite")
    kwargs = {"pool_pre_ping": True}
    if _is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(DATABASE_URL, **kwargs)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    init_db()
    return SessionLocal


_initialized_engine = None


def init_db():
    """Create the tables once per engine. ``create_all`` checks every table, which against a remote Postgres
    costs seconds, and callers (the dashboard's refresh, the brain's writes) invoke this on every call."""
    global _initialized_engine
    if _initialized_engine is engine:
        return
    from src.db.models import Base as ModelsBase
    ModelsBase.metadata.create_all(bind=engine)
    _initialized_engine = engine  # only after success, so a failed attempt is retried


def db_health() -> dict:
    """Lightweight connectivity probe for /health."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        backend = "sqlite" if _is_sqlite else "postgres"
        return {"ok": True, "backend": backend}
    except Exception as e:
        logger.warning("DB health check failed: %s", e)
        return {"ok": False, "backend": "sqlite" if _is_sqlite else "postgres", "error": str(e)}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
