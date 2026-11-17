import support  # noqa: F401
import os
import unittest
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from src.brain import main as brain_main
from src.brain.remediation import AlertDebouncer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POD = "chaos-shell-injection-7c9d5b6f4-abcde"


def falco_event(rule="Aegis Shell Spawned in Container", pod=POD, ns="aegis-chaos", **extra_fields):
    fields = {"k8s.pod.name": pod, "k8s.ns.name": ns, "proc.cmdline": "sh -i", "container.name": "shell-bait"}
    fields.update(extra_fields)
    return {"rule": rule, "priority": "Warning", "time": "2026-11-17T10:00:00Z",
            "output": "[SECURITY_ALERT] Shell spawned MITRE:T1059", "output_fields": fields}


class TestFalcoIngest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(brain_main.app)

    def setUp(self):
        brain_main.alert_debouncer.clear()
        p = mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "false", "AEGIS_ALERT_DEBOUNCE_S": "30"})
        p.start()
        self.addCleanup(p.stop)

    def _post(self, body):
        with mock.patch.object(brain_main.diagnostic_engine, "diagnose_incident",
                               return_value={"problem_type": "SECURITY_ATTACK"}) as diag:
            resp = self.client.post("/api/v1/alerts/falco", json=body)
        return resp, diag

    def test_event_maps_pod_namespace_and_alert_type(self):
        resp, diag = self._post(falco_event())
        self.assertEqual(resp.status_code, 200)
        kwargs = diag.call_args.kwargs
        self.assertEqual((kwargs["pod_name"], kwargs["namespace"], kwargs["alert_type"]),
                         (POD, "aegis-chaos", "falco_shell_spawn"))

    def test_known_rules_map_to_the_alert_types_the_brain_understands(self):
        expect = {
            "Aegis Shell Spawned in Container": "falco_shell_spawn",
            "Aegis Sensitive File Read": "falco_sensitive_file_read",
            "Aegis Network Discovery Tool Spawned": "falco_network_recon",
        }
        for rule, alert_type in expect.items():
            brain_main.alert_debouncer.clear()
            _, diag = self._post(falco_event(rule=rule))
            self.assertEqual(diag.call_args.kwargs["alert_type"], alert_type, rule)

    def test_alert_types_contain_a_falco_token_so_the_engine_pulls_security_evidence(self):
        for t in ("falco_shell_spawn", "falco_sensitive_file_read", "falco_network_recon"):
            self.assertIn("falco", t)

    def test_non_aegis_rules_are_ignored(self):
        resp, diag = self._post(falco_event(rule="Read sensitive file untrusted"))
        self.assertEqual(resp.json()["ignored"], True)
        diag.assert_not_called()

    def test_event_without_pod_identity_is_ignored(self):
        for fields in ({"k8s.pod.name": "<NA>"}, {"k8s.pod.name": ""}, {"k8s.ns.name": ""}):
            ev = falco_event()
            ev["output_fields"].update(fields)
            resp, diag = self._post(ev)
            self.assertTrue(resp.json()["ignored"], fields)
            diag.assert_not_called()

    def test_missing_output_fields_is_ignored_not_an_error(self):
        resp, diag = self._post({"rule": "Aegis Shell Spawned in Container"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ignored"])
        diag.assert_not_called()

    def test_repeat_events_are_debounced(self):
        r1, d1 = self._post(falco_event())
        r2, d2 = self._post(falco_event())
        self.assertNotIn("debounced", r1.json())
        self.assertTrue(r2.json()["debounced"])
        d1.assert_called_once()
        d2.assert_not_called()

    def test_different_pod_is_not_debounced(self):
        self._post(falco_event())
        resp, diag = self._post(falco_event(pod="other-pod-1"))
        self.assertNotIn("debounced", resp.json())
        diag.assert_called_once()

    def test_non_object_body_is_rejected(self):
        resp = self.client.post("/api/v1/alerts/falco", json=["not", "an", "object"])
        self.assertEqual(resp.status_code, 422)

    def test_auto_remediate_flag_routes_through_the_pipeline(self):
        fake = {"verdict": {"problem_type": "SECURITY_ATTACK"}, "decision": {}, "execution": {},
                "verified": True, "escalated": False, "escalation": None}
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true"}), mock.patch.object(
            brain_main, "process_alert", return_value=fake
        ) as pa:
            resp = self.client.post("/api/v1/alerts/falco", json=falco_event())
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["accepted"])  # work continues in the background
        self.assertEqual(pa.call_args.kwargs["alert_type"], "falco_shell_spawn")
        self.assertEqual(pa.call_args.kwargs["namespace"], "aegis-chaos")


class TestAlertDebouncer(unittest.TestCase):
    def test_window_expires(self):
        now = [100.0]
        d = AlertDebouncer(clock=lambda: now[0])
        self.assertTrue(d.allow("k", 30))
        self.assertFalse(d.allow("k", 30))
        now[0] = 131.0
        self.assertTrue(d.allow("k", 30))

    def test_zero_window_disables_debouncing(self):
        d = AlertDebouncer()
        self.assertTrue(d.allow("k", 0))
        self.assertTrue(d.allow("k", 0))


class TestFalcoManifestWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "k8s/monitoring/falco.yaml"), encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
        cls.cms = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ConfigMap"}

    def test_falco_posts_events_to_the_brain(self):
        cfg = yaml.safe_load(self.cms["falco-config"]["data"]["falco.yaml"])
        self.assertTrue(cfg["http_output"]["enabled"])
        self.assertEqual(cfg["http_output"]["url"], "http://aegis-brain.aegis-system.svc:8001/api/v1/alerts/falco")
        self.assertTrue(cfg["json_output"])

    def test_every_aegis_rule_reports_the_namespace(self):
        for path in ("k8s/monitoring/falco.yaml", "config/falco/falco_rules.local.yaml"):
            text = open(os.path.join(ROOT, path), encoding="utf-8").read()
            outputs = [ln for ln in text.splitlines() if "[SECURITY_ALERT]" in ln]
            self.assertGreaterEqual(len(outputs), 3, path)
            for ln in outputs:
                self.assertIn("ns=%k8s.ns.name", ln, f"{path}: {ln.strip()}")


if __name__ == "__main__":
    unittest.main()
