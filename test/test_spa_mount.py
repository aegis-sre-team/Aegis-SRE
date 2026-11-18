"""The dashboard server serves the React build when it exists and the legacy page otherwise.

Standalone on purpose: spa.py touches no DB or sensors, so this needs none of test/support.py.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.dashboard import spa


def _app(legacy: str):
    app = FastAPI()

    @app.get("/api/ping")
    def ping():
        return {"ok": True}

    return app, spa.mount_dashboard(app, legacy)


class SpaMountTests(unittest.TestCase):
    def test_serves_react_build_and_keeps_api_routes(self):
        with tempfile.TemporaryDirectory() as dist, tempfile.TemporaryDirectory() as legacy:
            Path(dist, "index.html").write_text("<title>Aegis console</title>", encoding="utf-8")
            Path(legacy, "index.html").write_text("legacy page", encoding="utf-8")
            with patch.dict(os.environ, {"AEGIS_FRONTEND_DIST": dist}):
                app, kind = _app(legacy)
            client = TestClient(app)
            self.assertEqual(kind, "react")
            self.assertEqual(client.get("/api/ping").json(), {"ok": True})
            self.assertIn("Aegis console", client.get("/").text)

    def test_falls_back_to_legacy_page_without_a_build(self):
        with tempfile.TemporaryDirectory() as empty, tempfile.TemporaryDirectory() as legacy:
            Path(legacy, "index.html").write_text("legacy page", encoding="utf-8")
            with patch.dict(os.environ, {"AEGIS_FRONTEND_DIST": empty}):
                app, kind = _app(legacy)
            self.assertEqual(kind, "legacy")
            self.assertIn("legacy page", TestClient(app).get("/").text)


if __name__ == "__main__":
    unittest.main()
