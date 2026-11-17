import support  # noqa: F401
import os
import tempfile
import unittest
from unittest import mock

import requests

from src.brain.collector import TelemetryCollector
from src.brain.diagnostic_engine import DiagnosticEngine
from src.controller.executor import ActionExecutor
from src.guardrails import GuardrailEngine
from src.guardrails.action_schema import GuardrailDecision, STATE_GUARDRAIL_APPROVED

POD = "cartservice-6f7d8c9b5-x2k4p"
NS = "online-boutique"


def verdict(action="RESTART_POD", target=POD, namespace=NS, **extra):
    v = {"target_pod": target, "problem_type": "OPERATIONAL_BUG", "recommended_action": action,
         "confidence": 0.9, "namespace": namespace}
    v.update(extra)
    return v


def decision(action, pod=POD, namespace=NS):
    return GuardrailDecision(approved=True, final_action=action, state=STATE_GUARDRAIL_APPROVED, reason="t",
                             confidence=0.9, original_action=action, target_pod=pod,
                             problem_type="OPERATIONAL_BUG", namespace=namespace)


def live_executor():
    tmp = tempfile.mkdtemp(prefix="aegis_r3_")
    return ActionExecutor(namespace="default", dry_run_mode=False,
                          audit_log_path=os.path.join(tmp, "a.jsonl"), forensics_dir=tmp)


# ------------------------------------------------------------------------- budget is spent only by acting
class TestRestartBudgetIsSpentOnlyWhenActing(unittest.TestCase):
    def setUp(self):
        support.reset_restart_state()
        self.g = GuardrailEngine(min_confidence_threshold=0.70, max_restarts_per_hour=3)
        self.g.reset_rate_limits()

    def test_diagnosing_without_reserving_never_consumes_the_budget(self):
        for i in range(6):
            d = self.g.validate_verdict(verdict(target=f"cartservice-6f7d8c9b5-a{i:04d}"), reserve_budget=False)
            self.assertTrue(d.approved, i)
        acting = [self.g.validate_verdict(verdict(target=f"cartservice-6f7d8c9b5-b{i:04d}")) for i in range(4)]
        self.assertEqual([d.approved for d in acting], [True, True, True, False])

    def test_peek_still_reports_an_exhausted_budget(self):
        for i in range(3):
            self.g.validate_verdict(verdict(target=f"cartservice-6f7d8c9b5-c{i:04d}"))
        peek = self.g.validate_verdict(verdict(target="cartservice-6f7d8c9b5-zzzzz"), reserve_budget=False)
        self.assertFalse(peek.approved)
        self.assertTrue(peek.rate_limit_exceeded)

    def test_engine_passes_the_flag_through(self):
        engine = DiagnosticEngine(guardrail=self.g)
        support.start_patches(self, support.sensor_patches(engine))
        llm = {"incident_id": "I", "problem_type": "OPERATIONAL_BUG", "recommended_action": "RESTART_POD",
               "confidence": 0.9, "root_cause": "x", "reasoning": "y", "threat_level": "HIGH"}
        with mock.patch.object(engine.llm, "generate_json_diagnosis", return_value=dict(llm)):
            for _ in range(5):
                v = engine.diagnose_incident(pod_name=POD, alert_type="OOM_KILLED_RISK", namespace=NS, reserve_budget=False)
                self.assertTrue(v["decision_object"].approved)
            v = engine.diagnose_incident(pod_name=POD, alert_type="OOM_KILLED_RISK", namespace=NS)
            self.assertTrue(v["decision_object"].approved, "diagnosing five times must not have spent the budget")


# ------------------------------------------------------------------------- caller-supplied alert types are not trusted
class TestTrustedSignalNeedsATrustedSource(unittest.TestCase):
    def setUp(self):
        support.reset_restart_state()
        self.engine = DiagnosticEngine()
        support.start_patches(self, support.sensor_patches(self.engine))
        self.llm = {"incident_id": "I", "problem_type": "OPERATIONAL_BUG", "recommended_action": "RESTART_POD",
                    "confidence": 0.3, "root_cause": "x", "reasoning": "y", "threat_level": "LOW"}

    def _run(self, **kw):
        with mock.patch.object(self.engine.llm, "generate_json_diagnosis", return_value=dict(self.llm)):
            return self.engine.diagnose_incident(pod_name=POD, alert_type="falco_shell_spawn", namespace=NS, **kw)

    def test_default_caller_cannot_force_a_quarantine_with_an_alert_type_string(self):
        v = self._run()
        self.assertNotIn("_trusted_signal_override", v)
        self.assertFalse(v["decision_object"].approved)  # 0.3 confidence still fails the gate

    def test_a_trusted_source_gets_the_override(self):
        v = self._run(trusted_signal=True)
        self.assertTrue(v["_trusted_signal_override"])
        self.assertEqual(v["decision_object"].final_action, "CILIUM_QUARANTINE_EBPF")

    def test_ingest_endpoints_are_trusted_and_the_api_is_not(self):
        from fastapi.testclient import TestClient
        from src.brain import main as brain_main

        client = TestClient(brain_main.app)
        brain_main.alert_debouncer.clear()
        seen = {}

        def fake(self_, pod_name, alert_type, namespace=None, **kw):
            seen.update(kw)
            return {"problem_type": "X"}

        with mock.patch.object(DiagnosticEngine, "diagnose_incident", fake):
            client.post("/api/v1/alerts/falco", json={"rule": "Aegis Shell Spawned in Container",
                        "output_fields": {"k8s.pod.name": POD, "k8s.ns.name": NS}})
            self.assertTrue(seen.get("trusted_signal"))
            seen.clear()
            client.post("/api/v1/diagnose", json={"pod_name": POD, "alert_type": "falco_shell_spawn"})
            self.assertFalse(seen.get("trusted_signal"))
            self.assertIs(seen.get("reserve_budget"), False, "/diagnose must not spend the restart budget")


# ------------------------------------------------------------------------- Falco namespace token matching
class TestFalcoNamespaceMatchingIsExact(unittest.TestCase):
    def _alerts(self, lines, namespace):
        body = mock.Mock(status_code=200)
        body.json.return_value = {"data": {"result": [{"values": [[str(i), l] for i, l in enumerate(lines)]}]}}
        c = TelemetryCollector(prometheus_url="http://p", loki_url="http://l")
        with mock.patch("requests.get", return_value=body):
            return c.fetch_falco_alerts("web-1", namespace=namespace)

    def test_a_longer_namespace_does_not_match(self):
        lines = ["[SECURITY_ALERT] shell (user=root ns=production pod=web-1 cmd=sh)",
                 "[SECURITY_ALERT] shell (user=root ns=prod pod=web-1 cmd=sh)"]
        got = self._alerts(lines, "prod")
        self.assertEqual(len(got), 1)
        self.assertIn("ns=prod ", got[0])

    def test_unrelated_text_that_contains_ns_is_not_a_namespace_token(self):
        lines = ["falco notice sessions=3 options=x pod=web-1 something happened"]
        self.assertEqual(self._alerts(lines, "prod"), lines)  # no real ns= token: legacy line, kept

    def test_a_line_for_the_right_namespace_is_kept_even_with_other_ns_like_text(self):
        lines = ["[SECURITY_ALERT] x (sessions=3 ns=prod pod=web-1)"]
        self.assertEqual(self._alerts(lines, "prod"), lines)


# ------------------------------------------------------------------------- unquarantine record only after success
class TestUnquarantineRecordFollowsTheOutcome(unittest.TestCase):
    def setUp(self):
        support.reset_quarantine_state()
        self.ex = live_executor()
        self.ex._record_quarantine_db(POD, NS, active=True)
        p = mock.patch.dict(os.environ, {"AEGIS_ALLOW_KUBECTL_FALLBACK": "true"})
        p.start()
        self.addCleanup(p.stop)

    def _active(self):
        from src.db.database import SessionLocal
        from src.db.models import QuarantineRecord

        with SessionLocal() as s:
            return s.query(QuarantineRecord).filter_by(target_pod=f"{NS}/{POD}").first().active

    def test_failed_release_keeps_the_record_active(self):
        failed = mock.Mock(returncode=1, stdout="", stderr="timeout")
        with mock.patch("subprocess.run", return_value=failed):
            result = self.ex.unquarantine_pod_ebpf(POD, namespace=NS)
        self.assertFalse(result.success)
        self.assertTrue(self._active(), "the pod is still caged, so the record must stay active")

    def test_successful_release_clears_it(self):
        ok = mock.Mock(returncode=0, stdout="deleted", stderr="")
        with mock.patch("subprocess.run", return_value=ok):
            result = self.ex.unquarantine_pod_ebpf(POD, namespace=NS)
        self.assertTrue(result.success)
        self.assertFalse(self._active())


# ------------------------------------------------------------------------- scale fallback semantics
class TestScaleFallbackMatchesTheController(unittest.TestCase):
    def setUp(self):
        self.ex = live_executor()
        p = mock.patch.dict(os.environ, {"AEGIS_ALLOW_KUBECTL_FALLBACK": "true", "MAX_REPLICAS": "4"})
        p.start()
        self.addCleanup(p.stop)

    def _scale(self, current):
        owner = mock.Mock(returncode=0, stdout="ReplicaSet cartservice-6f7d8c9b5", stderr="")
        reps = mock.Mock(returncode=0, stdout=str(current), stderr="")
        done = mock.Mock(returncode=0, stdout="scaled", stderr="")
        with mock.patch("subprocess.run", side_effect=[owner, reps, done]) as run, mock.patch.object(
            self.ex, "verify_remediation_health", return_value=True
        ):
            result = self.ex.scale_deployment(POD, namespace=NS)
        return result, run.call_args_list[2].args[0]

    def test_scales_up_by_one_never_down(self):
        result, cmd = self._scale(3)
        self.assertTrue(result.success)
        self.assertIn("--replicas=4", cmd)

    def test_respects_the_cap(self):
        _, cmd = self._scale(4)
        self.assertIn("--replicas=4", cmd)

    def test_a_single_replica_becomes_two(self):
        _, cmd = self._scale(1)
        self.assertIn("--replicas=2", cmd)

    def test_dry_run_says_scale_up_by_one(self):
        ex = ActionExecutor(namespace="default", dry_run_mode=True)
        details = ex.scale_deployment(POD, namespace=NS).details
        self.assertIn("up by one", details)


# ------------------------------------------------------------------------- verification follows who acted
class TestVerificationFollowsWhoActed(unittest.TestCase):
    def setUp(self):
        self.ex = live_executor()
        env = {"AEGIS_ALLOW_KUBECTL_FALLBACK": "true",
               "GO_CONTROLLER_URL": "http://aegis-controller.aegis-system.svc:8080/api/v1/reconcile"}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)

    def test_controller_actions_are_verified_through_the_controller_even_with_the_fallback_flag(self):
        ok = mock.Mock(status_code=200)
        ok.json.return_value = {"status": "success", "mode": "k8s_cluster", "message": "released"}
        status = mock.Mock(status_code=200)
        status.json.return_value = {"found": True, "phase": "Running", "ready": True, "quarantined": False}
        with mock.patch("requests.post", return_value=ok), mock.patch("requests.get", return_value=status), mock.patch(
            "subprocess.run"
        ) as run:
            result = self.ex.execute_decision(decision("UNQUARANTINE_POD"))
        self.assertTrue(result.success)
        self.assertTrue(result.health_verified)
        run.assert_not_called()  # a brain with no kubectl must not be asked to run it

    def test_kubectl_verification_checks_the_policy_for_quarantine_and_release(self):
        present = mock.Mock(returncode=0, stdout="aegis-quarantine-x", stderr="")
        absent = mock.Mock(returncode=1, stdout="", stderr="NotFound")
        with mock.patch("subprocess.run", return_value=present):
            self.assertTrue(self.ex._verify_via_kubectl(POD, "CILIUM_QUARANTINE_EBPF", NS, None))
            self.assertFalse(self.ex._verify_via_kubectl(POD, "UNQUARANTINE_POD", NS, None))
        with mock.patch("subprocess.run", return_value=absent):
            self.assertFalse(self.ex._verify_via_kubectl(POD, "CILIUM_QUARANTINE_EBPF", NS, None))
            self.assertTrue(self.ex._verify_via_kubectl(POD, "UNQUARANTINE_POD", NS, None))


if __name__ == "__main__":
    unittest.main()
