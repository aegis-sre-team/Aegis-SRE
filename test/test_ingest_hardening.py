import support  # noqa: F401
import os
import threading
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from src.brain import main as brain_main
from src.brain.remediation import AlertDebouncer, is_valid_k8s_name

POD = "chaos-shell-injection-7c9d5b6f4-abcde"
NS = "aegis-chaos"


def falco(pod=POD, ns=NS, rule="Aegis Shell Spawned in Container"):
    return {"rule": rule, "priority": "Warning", "output": "x",
            "output_fields": {"k8s.pod.name": pod, "k8s.ns.name": ns}}


def webhook(pod=POD, ns=NS, alertname="AegisHighPodCPU"):
    return {"status": "firing", "alerts": [{"status": "firing", "annotations": {},
            "labels": {"alertname": alertname, "pod": pod, "namespace": ns}}]}


class IngestTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(brain_main.app)

    def setUp(self):
        brain_main.alert_debouncer.clear()
        env = {"AEGIS_AUTO_REMEDIATE": "false", "AEGIS_ALERT_DEBOUNCE_S": "30", "AEGIS_INGEST_TOKEN": ""}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("AEGIS_ALLOWED_NAMESPACES", None)


class TestNameValidation(unittest.TestCase):
    def test_valid_and_invalid_names(self):
        for ok in ("cartservice-6f7d8c9b5-x2k4p", "a", "web.1", "online-boutique"):
            self.assertTrue(is_valid_k8s_name(ok), ok)
        for bad in ("", "../../etc/passwd", "Upper", "-lead", "trail-", "a b", "x" * 254, "a/b", "a\\b", None, 5):
            self.assertFalse(is_valid_k8s_name(bad), repr(bad))


class TestFalcoScope(IngestTestCase):
    def _post(self, body):
        with mock.patch.object(brain_main.diagnostic_engine, "diagnose_incident",
                               return_value={"problem_type": "SECURITY_ATTACK"}) as diag:
            return self.client.post("/api/v1/alerts/falco", json=body), diag

    def test_invalid_pod_or_namespace_name_is_ignored(self):
        for pod, ns in (("../../etc", NS), ("UPPER", NS), ("x" * 300, NS), (POD, "bad ns"), (POD, "../x")):
            resp, diag = self._post(falco(pod=pod, ns=ns))
            self.assertTrue(resp.json()["ignored"], (pod[:20], ns))
            diag.assert_not_called()

    def test_protected_namespace_is_ignored_without_an_llm_call(self):
        resp, diag = self._post(falco(ns="kube-system"))
        body = resp.json()
        self.assertTrue(body["ignored"])
        self.assertIn("not managed", body["reason"])
        diag.assert_not_called()

    def test_namespace_outside_the_allowlist_is_ignored(self):
        with mock.patch.dict(os.environ, {"AEGIS_ALLOWED_NAMESPACES": "online-boutique"}):
            resp, diag = self._post(falco(ns="aegis-chaos"))
        self.assertTrue(resp.json()["ignored"])
        diag.assert_not_called()

    def test_failed_handling_releases_the_debounce_key_so_a_retry_can_run(self):
        with mock.patch.object(brain_main, "_handle_alert", return_value={"error": "llm down"}) as handler:
            self.client.post("/api/v1/alerts/falco", json=falco())
            second = self.client.post("/api/v1/alerts/falco", json=falco())
        self.assertNotIn("debounced", second.json())
        self.assertEqual(handler.call_count, 2)


class TestIngestToken(IngestTestCase):
    def _all_endpoints(self, headers):
        out = {}
        with mock.patch.object(brain_main.diagnostic_engine, "diagnose_incident",
                               return_value={"problem_type": "X", "decision_object": None}), mock.patch.object(
            brain_main, "process_alert",
            return_value={"verdict": {}, "decision": None, "execution": None, "verified": False,
                          "escalated": True, "escalation": None, "dry_run": True},
        ):
            out["falco"] = self.client.post("/api/v1/alerts/falco", json=falco(), headers=headers).status_code
            brain_main.alert_debouncer.clear()
            out["webhook"] = self.client.post("/api/v1/alerts/webhook", json=webhook(), headers=headers).status_code
            out["diagnose"] = self.client.post("/api/v1/diagnose", json={"pod_name": POD}, headers=headers).status_code
            out["remediate"] = self.client.post("/api/v1/remediate", json={"pod_name": POD}, headers=headers).status_code
        return out

    def test_open_when_no_token_is_configured(self):
        self.assertTrue(all(code == 200 for code in self._all_endpoints({}).values()))

    def test_token_required_on_every_action_endpoint_when_configured(self):
        with mock.patch.dict(os.environ, {"AEGIS_INGEST_TOKEN": "s3cret"}):
            self.assertTrue(all(c == 401 for c in self._all_endpoints({}).values()))
            self.assertTrue(all(c == 401 for c in self._all_endpoints({"X-Aegis-Token": "wrong"}).values()))
            self.assertTrue(all(c == 200 for c in self._all_endpoints({"X-Aegis-Token": "s3cret"}).values()))
            self.assertTrue(all(c == 200 for c in self._all_endpoints({"Authorization": "Bearer s3cret"}).values()))

    def test_health_stays_open(self):
        with mock.patch.dict(os.environ, {"AEGIS_INGEST_TOKEN": "s3cret"}):
            self.assertEqual(self.client.get("/health").status_code, 200)


class TestAutoRemediateRunsInTheBackground(IngestTestCase):
    FAKE = {"verdict": {}, "decision": {}, "execution": {}, "verified": True, "escalated": False,
            "escalation": None, "dry_run": False}

    def test_falco_returns_accepted_and_still_runs_the_pipeline(self):
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true"}), mock.patch.object(
            brain_main, "process_alert", return_value=self.FAKE
        ) as pa:
            resp = self.client.post("/api/v1/alerts/falco", json=falco())
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["accepted"])
        pa.assert_called_once()
        self.assertEqual(pa.call_args.kwargs["alert_type"], "falco_shell_spawn")

    def test_webhook_returns_accepted_and_still_runs_the_pipeline(self):
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true"}), mock.patch.object(
            brain_main, "process_alert", return_value=self.FAKE
        ) as pa:
            resp = self.client.post("/api/v1/alerts/webhook", json=webhook())
        self.assertTrue(resp.json()["diagnoses"][0]["accepted"])
        pa.assert_called_once()
        self.assertEqual(pa.call_args.kwargs["namespace"], NS)

    def test_webhook_repeats_are_debounced_when_acting(self):
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true"}), mock.patch.object(
            brain_main, "process_alert", return_value=self.FAKE
        ) as pa:
            self.client.post("/api/v1/alerts/webhook", json=webhook())
            second = self.client.post("/api/v1/alerts/webhook", json=webhook())
        self.assertTrue(second.json()["diagnoses"][0]["debounced"])
        pa.assert_called_once()

    def test_diagnose_only_webhook_stays_synchronous_and_returns_the_verdict(self):
        with mock.patch.object(brain_main.diagnostic_engine, "diagnose_incident",
                               return_value={"problem_type": "OPERATIONAL_BUG"}):
            resp = self.client.post("/api/v1/alerts/webhook", json=webhook())
        entry = resp.json()["diagnoses"][0]
        self.assertEqual(entry["verdict"]["problem_type"], "OPERATIONAL_BUG")
        self.assertNotIn("accepted", entry)

    def test_webhook_rejects_invalid_pod_names_without_acting(self):
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true"}), mock.patch.object(
            brain_main, "process_alert", return_value=self.FAKE
        ) as pa:
            resp = self.client.post("/api/v1/alerts/webhook", json=webhook(pod="../../x"))
        self.assertTrue(resp.json()["diagnoses"][0]["skipped"])
        pa.assert_not_called()


class TestDebouncer(unittest.TestCase):
    def test_thread_safe_exactly_one_winner(self):
        d = AlertDebouncer()
        wins = []

        def go():
            if d.allow("k", 30):
                wins.append(1)

        threads = [threading.Thread(target=go) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)

    def test_stale_entries_are_pruned(self):
        now = [0.0]
        d = AlertDebouncer(clock=lambda: now[0])
        for i in range(1200):
            d.allow(f"k{i}", 30)
        now[0] = 5000.0
        d.allow("fresh", 30)
        self.assertEqual(len(d._seen), 1)

    def test_release_allows_an_immediate_retry(self):
        d = AlertDebouncer()
        self.assertTrue(d.allow("k", 30))
        self.assertFalse(d.allow("k", 30))
        d.release("k")
        self.assertTrue(d.allow("k", 30))
        d.release("never-seen")  # must not raise


if __name__ == "__main__":
    unittest.main()
