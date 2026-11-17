"""Guards the test harness itself: tests must never touch the real DB or call a real LLM."""
import os
import unittest

import support  # noqa: F401  (must be imported before any src.* module)


class TestIsolation(unittest.TestCase):
    def test_database_is_temp(self):
        url = os.environ["DATABASE_URL"]
        self.assertTrue(url.startswith("sqlite:///"))
        self.assertNotIn("logs", url.replace("\\", "/").split("/")[-2:])
        self.assertIn("aegis_test_", url)

    def test_audit_dir_is_temp(self):
        self.assertIn("aegis_test_", os.environ["AEGIS_DB_DIR"])

    def test_llm_has_no_cloud_keys(self):
        self.assertEqual(os.environ["GROQ_API_KEY"], "")
        self.assertEqual(os.environ["GEMINI_API_KEY"], "")

    def test_ollama_points_at_closed_port(self):
        self.assertIn("127.0.0.1:9", os.environ["OLLAMA_HOST"])

    def test_sensor_patches_make_engine_honest_and_fast(self):
        from src.brain.diagnostic_engine import DiagnosticEngine

        engine = DiagnosticEngine()
        support.start_patches(self, support.sensor_patches(engine))
        self.assertFalse(engine.collector.any_critical_dark())
        verdict = engine.diagnose_incident(pod_name="iso-pod-1", alert_type="HTTP_500_SPIKE")
        self.assertNotEqual(verdict["problem_type"], "SENSOR_DARK")


if __name__ == "__main__":
    unittest.main()
