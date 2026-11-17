import support  # noqa: F401
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from src.brain import main as brain_main
from src.guardrails.action_schema import STATE_ACTION_REJECTED


def _webhook(namespace, pod="cartservice-6f7d8c9b5-x2k4p", alertname="AegisHighPodCPU"):
    return {
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": alertname, "pod": pod, "namespace": namespace},
                "annotations": {},
            }
        ],
    }


class TestNamespacePropagation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(brain_main.app)

    def setUp(self):
        support.reset_restart_state()
        support.start_patches(self, support.sensor_patches(brain_main.diagnostic_engine))

    def test_diagnose_incident_sets_namespace_on_verdict_and_decision(self):
        v = brain_main.diagnostic_engine.diagnose_incident(
            pod_name="cartservice-6f7d8c9b5-x2k4p",
            alert_type="OOM_KILLED_RISK",
            namespace="online-boutique",
        )
        self.assertEqual(v["namespace"], "online-boutique")
        self.assertEqual(v["decision_object"].namespace, "online-boutique")

    def test_sensor_dark_escalation_keeps_namespace(self):
        engine = brain_main.diagnostic_engine
        with mock.patch.object(engine.collector, "any_critical_dark", return_value=True):
            v = engine.diagnose_incident(pod_name="p1", alert_type="OOM", namespace="online-boutique")
        self.assertEqual(v["problem_type"], "SENSOR_DARK")
        self.assertEqual(v["decision_object"].namespace, "online-boutique")

    def test_webhook_passes_namespace_label_to_engine(self):
        with mock.patch.object(
            brain_main.diagnostic_engine, "diagnose_incident", return_value={"problem_type": "X"}
        ) as diag:
            resp = self.client.post("/api/v1/alerts/webhook", json=_webhook("online-boutique"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(diag.call_args.kwargs["namespace"], "online-boutique")

    def test_webhook_in_protected_namespace_is_rejected_by_guardrails(self):
        resp = self.client.post("/api/v1/alerts/webhook", json=_webhook("kube-system", pod="coredns-abc-123"))
        self.assertEqual(resp.status_code, 200)
        verdict = resp.json()["diagnoses"][0]["verdict"]
        self.assertEqual(verdict["guardrail_validation"]["state"], STATE_ACTION_REJECTED)
        self.assertEqual(verdict["recommended_action"], "ESCALATE")


class TestAlertTypeMapping(unittest.TestCase):
    def _type(self, name, summary="", path="bug"):
        return brain_main._alert_type_from_labels(
            {"alertname": name, "aegis_path": path}, {"summary": summary})

    def test_crashloop_and_oom_alert_names_map_to_alert_types(self):
        self.assertEqual(self._type("AegisPodCrashLooping"), "CRASHLOOP_BACKOFF")
        self.assertEqual(self._type("AegisContainerOOMKilled"), "OOM_KILLED_RISK")
        self.assertEqual(self._type("AegisHighPodCPU"), "AegisHighPodCPU")

    def test_a_pod_named_shell_does_not_turn_a_bug_alert_into_a_security_alert(self):
        summary = "High CPU on aegis-chaos/chaos-shell-injection-7c9d5b6f4-abcde"
        self.assertEqual(self._type("AegisHighPodCPU", summary), "AegisHighPodCPU")
        self.assertEqual(self._type("AegisContainerOOMKilled", summary), "OOM_KILLED_RISK")
        self.assertEqual(self._type("AegisPodCrashLooping", summary), "CRASHLOOP_BACKOFF")

    def test_a_falco_named_alert_is_still_a_security_alert(self):
        self.assertEqual(self._type("FalcoShellSpawn"), "falco_shell_spawn")
        self.assertEqual(self._type("Whatever", path="attack"), "falco_shell_spawn")

    def test_crashloop_fallback_is_a_bounded_restart(self):
        verdict = brain_main.diagnostic_engine.llm._rule_based_fallback(
            "Target Pod: chaos-crashloop-abc-12345\nAlert Event: CRASHLOOP_BACKOFF\nmetrics...")
        self.assertEqual(verdict["recommended_action"], "RESTART_POD")
        self.assertEqual(verdict["problem_type"], "OPERATIONAL_BUG")
        self.assertAlmostEqual(verdict["confidence"], 0.80)
        self.assertIn("crash", verdict["root_cause"].lower())


if __name__ == "__main__":
    unittest.main()
