"""Shared test harness. Import this FIRST in every test module (before any ``src.*`` import).

It makes the suite hermetic and deterministic:
  * a throw-away SQLite DB and audit dir, so restart counters and audit rows never
    leak between runs or into ``logs/``;
  * no cloud LLM keys and an Ollama host on a closed port, so diagnosis always uses
    the built-in rule engine (``load_dotenv`` never overrides variables already set);
  * ``sensor_patches`` to stand in for Prometheus/Loki/Falco, because the engine is
    deliberately fail-closed when sensors are dark.
"""
import atexit
import os
import shutil
import tempfile
from unittest.mock import patch

_TMP = tempfile.mkdtemp(prefix="aegis_test_")
atexit.register(lambda: shutil.rmtree(_TMP, ignore_errors=True))

os.environ["AEGIS_DB_DIR"] = _TMP
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_TMP, "aegis_test.db").replace("\\", "/")
os.environ["GROQ_API_KEY"] = ""
os.environ["GEMINI_API_KEY"] = ""
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:9"
os.environ.setdefault("AEGIS_SENSOR_TIMEOUT", "0.5")
os.environ.pop("AEGIS_ALLOWED_NAMESPACES", None)
os.environ.pop("GO_CONTROLLER_TOKEN", None)
os.environ["DASHBOARD_MODE"] = "demo"  # never probe a real controller from unit tests
TEMP_DIR = _TMP

DEFAULT_METRICS = {
    "total_requests": 100,
    "error_500_count": 25,
    "avg_latency_ms": 40.0,
    "memory_mb": 200.0,
    "memory_limit_mb": 512.0,
    "memory_pct": 39.0,
    "cpu_usage_pct": 30.0,
    "sensor_ok": True,
    "source": "test-mock",
}

HEALTHY_SENSORS = {
    "prometheus": {"ok": True, "detail": "mock"},
    "loki": {"ok": True, "detail": "mock"},
    "falco_via_loki": {"ok": True, "detail": "mock"},
}


def sensor_patches(engine, metrics=None, falco_events=None, logs=None):
    """Patches that make ``engine.collector`` report healthy sensors with the given evidence."""
    collector = engine.collector
    return [
        patch.object(collector, "check_sensors", return_value=dict(HEALTHY_SENSORS)),
        patch.object(collector, "any_critical_dark", return_value=False),
        patch.object(collector, "fetch_prometheus_metrics",
                     return_value=dict(metrics or DEFAULT_METRICS)),
        patch.object(collector, "fetch_loki_logs",
                     return_value=list(logs if logs is not None else ["[ERROR] database connection failure"])),
        patch.object(collector, "fetch_falco_alerts", return_value=list(falco_events or [])),
    ]


def reset_restart_state():
    """Clear persisted restart events so the 3-restarts/hour guardrail starts fresh."""
    from src.db.database import SessionLocal, init_db
    from src.db.models import RestartEventRecord

    init_db()
    with SessionLocal() as session:
        session.query(RestartEventRecord).delete()
        session.commit()


def reset_quarantine_state():
    """Remove persisted quarantine records so a test starts with no active cage."""
    from src.db.database import SessionLocal, init_db
    from src.db.models import QuarantineRecord

    init_db()
    with SessionLocal() as session:
        session.query(QuarantineRecord).delete()
        session.commit()


def restore_default_database():
    """Point the global DB back at this run's temp database (after a test swapped it)."""
    from src.db.database import configure_database

    configure_database(os.environ["DATABASE_URL"])


def start_patches(testcase, patches):
    """Start patches and guarantee they are stopped when the test (or class) finishes."""
    for p in patches:
        p.start()
    cleanup = testcase.addClassCleanup if isinstance(testcase, type) else testcase.addCleanup
    for p in patches:
        cleanup(p.stop)
