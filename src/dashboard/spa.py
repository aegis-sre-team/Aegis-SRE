"""Serves the React console (frontend/dist) from the dashboard server, with the legacy page as fallback."""
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger("aegis-dashboard-server")

REPO_ROOT = Path(__file__).resolve().parents[2]


def frontend_dist() -> Optional[Path]:
    """The built console, or None when `npm run build` has not been run. AEGIS_FRONTEND_DIST overrides."""
    dist = Path(os.getenv("AEGIS_FRONTEND_DIST") or REPO_ROOT / "frontend" / "dist")
    return dist if (dist / "index.html").is_file() else None


def mount_dashboard(app: FastAPI, legacy_dir: str) -> str:
    """Mount the React build at ``/`` if it exists, else the legacy static page. Returns which one.

    Routing in the console is hash-based, so no server-side fallback route is needed. Mount this after
    all API and WebSocket routes: a ``/`` mount shadows anything registered later.
    """
    dist = frontend_dist()
    if dist is not None:
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="console")
        logger.info("Serving the React console from %s", dist)
        return "react"
    os.makedirs(legacy_dir, exist_ok=True)
    app.mount("/", StaticFiles(directory=legacy_dir, html=True), name="static")
    logger.info("frontend/dist not found; serving the legacy dashboard. Run `npm run build` in frontend/.")
    return "legacy"
