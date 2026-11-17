import support  # noqa: F401
import os
import tempfile
import unittest
from unittest import mock

import requests

from src.brain.notifications import EscalationNotifier
from src.brain.remediation import process_alert
from src.controller.executor import ActionExecutionResult, ActionExecutor
from src.guardrails.action_schema import (
    GuardrailDecision,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN,
    STATE_GUARDRAIL_APPROVED,
)

POD = "cartservice-6f7d8c9b5-x2k4p"
NS = "online-boutique"
STATUS_URL = "http://aegis-controller.aegis-system.svc:8080/api/v1/status"


def _decision(action="RESTART_POD", approved=True, state=STATE_GUARDRAIL_APPROVED, problem="OPERATIONAL_BUG"):
    return GuardrailDecision(
        approved=approved, final_action=action if approved else "ESCALATE", state=state,
        reason="because", confidence=0.9, original_action=action, target_pod=POD,
        problem_type=problem, mitre_technique="T1059" if problem == "SECURITY_ATTACK" else None, namespace=NS,
    )


class FakeEngine:
    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    def diagnose_incident(self, pod_name, alert_type, namespace=None, **kw):
        self.calls.append((pod_name, alert_type, namespace))
        return {"incident_id": "INC-1", "target_pod": pod_name, "namespace": namespace,
                "problem_type": self.decision.problem_type, "root_cause": "rc",
                "recommended_action": self.decision.final_action, "decision_object": self.decision}


class FakeExecutor:
    def __init__(self, result):
        self.result = result
        self.executed = []

    def execute_decision(self, decision):
        self.executed.append(decision)
        return self.result


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def dispatch_escalation(self, decision, verdict):
        self.sent.append((decision, verdict))
        return {"webhook_status": "SKIPPED_NO_URL", "guardrail_reason": decision.reason}


def _ok(action="RESTART_POD", health=True):
    return ActionExecutionResult(True, action, POD, "done", "COMPLETED_GO_K8S_CLUSTER", health_verified=health)


class TestProcessAlert(unittest.TestCase):
    def _run(self, decision, result):
        engine, executor, notifier = FakeEngine(decision), FakeExecutor(result), FakeNotifier()
        out = process_alert(engine, executor, notifier, POD, "OOM_KILLED_RISK", namespace=NS)
        return out, engine, executor, notifier

    def test_bug_path_restart_verified_no_escalation(self):
        out, engine, executor, notifier = self._run(_decision(), _ok())
        self.assertTrue(out["verified"])
        self.assertFalse(out["escalated"])
        self.assertEqual(notifier.sent, [])
        self.assertEqual(engine.calls, [(POD, "OOM_KILLED_RISK", NS)])
        self.assertEqual(len(executor.executed), 1)

    def test_attack_path_quarantine_verified(self):
        d = _decision("CILIUM_QUARANTINE_EBPF", problem="SECURITY_ATTACK")
        out, _, executor, notifier = self._run(d, _ok("CILIUM_QUARANTINE_EBPF"))
        self.assertTrue(out["verified"])
        self.assertFalse(out["escalated"])
        self.assertEqual(executor.executed[0].final_action, "CILIUM_QUARANTINE_EBPF")

    def test_failed_verification_escalates_and_notifies(self):
        out, _, _, notifier = self._run(_decision(), _ok(health=False))
        self.assertFalse(out["verified"])
        self.assertTrue(out["escalated"])
        self.assertEqual(len(notifier.sent), 1)
        esc_decision = notifier.sent[0][0]
        self.assertEqual(esc_decision.state, STATE_ESCALATE_HUMAN)
        self.assertEqual(esc_decision.final_action, "ESCALATE")
        self.assertFalse(esc_decision.approved)
        self.assertIn("verification", esc_decision.reason.lower())
        self.assertEqual(esc_decision.original_action, "RESTART_POD")
        self.assertEqual(esc_decision.namespace, NS)

    def test_failed_execution_escalates(self):
        bad = ActionExecutionResult(False, "RESTART_POD", POD, "Go controller unreachable", "FAILED_CONTROLLER_UNREACHABLE")
        out, _, _, notifier = self._run(_decision(), bad)
        self.assertTrue(out["escalated"])
        self.assertFalse(out["verified"])
        self.assertIn("FAILED_CONTROLLER_UNREACHABLE", notifier.sent[0][0].reason)

    def test_unapproved_decision_escalates_without_executing(self):
        d = _decision(approved=False, state=STATE_ACTION_REJECTED)
        out, _, executor, notifier = self._run(d, _ok())
        self.assertEqual(executor.executed, [])
        self.assertTrue(out["escalated"])
        self.assertEqual(len(notifier.sent), 1)

    def test_escalate_decision_notifies_humans_without_executing_cluster_change(self):
        d = _decision("ESCALATE")
        out, _, executor, notifier = self._run(d, _ok("ESCALATE"))
        self.assertTrue(out["escalated"])
        self.assertEqual(len(notifier.sent), 1)
        self.assertEqual(executor.executed, [])

    def test_result_shape_for_api_consumers(self):
        out, *_ = self._run(_decision(), _ok())
        for key in ("verdict", "decision", "execution", "verified", "escalated", "escalation"):
            self.assertIn(key, out)
        self.assertNotIn("decision_object", out["verdict"])

    def test_result_reports_whether_the_run_was_dry(self):
        class DryExecutor(FakeExecutor):
            dry_run_mode = True

        dry = process_alert(FakeEngine(_decision()), DryExecutor(_ok()), FakeNotifier(), POD, "x", namespace=NS)
        live = process_alert(FakeEngine(_decision()), FakeExecutor(_ok()), FakeNotifier(), POD, "x", namespace=NS)
        self.assertTrue(dry["dry_run"])
        self.assertFalse(live["dry_run"])
        self.assertIsNone(dry["verified"], "a dry run changed nothing, so nothing was verified")
        self.assertTrue(live["verified"])

    def test_real_notifier_logs_to_the_path_it_was_given(self):
        tmp = tempfile.mkdtemp(prefix="aegis_esc_")
        notifier = EscalationNotifier(log_path=os.path.join(tmp, "esc.jsonl"), webhook_url="")
        engine, executor = FakeEngine(_decision()), FakeExecutor(_ok(health=False))
        out = process_alert(engine, executor, notifier, POD, "OOM_KILLED_RISK", namespace=NS)
        self.assertTrue(out["escalated"])
        self.assertTrue(os.path.exists(os.path.join(tmp, "esc.jsonl")))


def _status(found=True, ready=True, quarantined=False, dep=None):
    body = {"found": found, "phase": "Running" if found else "", "ready": ready, "restarts": 0, "quarantined": quarantined}
    if dep is not None:
        body["deployment"] = dep
    resp = mock.Mock()
    resp.status_code = 200
    resp.json.return_value = body
    return resp


def _rolled_out(desired=1, **over):
    d = {"name": "cartservice", "desired": desired, "ready": desired, "updated": desired,
         "replicas": desired, "generation": 2, "observed_generation": 2}
    d.update(over)
    return d


class TestVerifyRemediationHealth(unittest.TestCase):
    def setUp(self):
        self.executor = ActionExecutor(namespace="default", dry_run_mode=False,
                                       audit_log_path=os.path.join(tempfile.mkdtemp(), "a.jsonl"))
        env = {"GO_CONTROLLER_URL": "http://aegis-controller.aegis-system.svc:8080/api/v1/reconcile",
               "GO_CONTROLLER_TOKEN": "tok"}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        self.executor._sleep = lambda _s: None

    def _verify(self, responses, action="RESTART_POD", workload="cartservice", timeout=1.0, interval=0.0):
        side = responses if isinstance(responses, list) else responses
        with mock.patch("requests.get", side_effect=side) as get:
            ok = self.executor.verify_remediation_health(POD, action, NS, workload, timeout=timeout, interval=interval)
        return ok, get

    def test_dry_run_is_true_without_any_network_call(self):
        ex = ActionExecutor(namespace="default", dry_run_mode=True)
        with mock.patch("requests.get") as get:
            self.assertTrue(ex.verify_remediation_health(POD, "RESTART_POD", NS, "cartservice"))
        get.assert_not_called()

    def test_pod_gone_but_deployment_rolled_out_is_healthy(self):
        ok, get = self._verify([_status(found=False, dep=_rolled_out())] * 3)
        self.assertTrue(ok)
        url = get.call_args.args[0]
        self.assertTrue(url.startswith(STATUS_URL))
        self.assertEqual(get.call_args.kwargs["params"], {"namespace": NS, "pod": POD, "deployment": "cartservice"})
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"], "Bearer tok")

    def test_pod_gone_without_rollout_is_unhealthy(self):
        stuck = _status(found=False, dep=_rolled_out(ready=0))
        ok, _ = self._verify([stuck] * 50, timeout=0.05, interval=0.0)
        self.assertFalse(ok)

    def test_pod_gone_and_no_deployment_info_is_unhealthy(self):
        ok, _ = self._verify([_status(found=False)] * 50, workload=None, timeout=0.05)
        self.assertFalse(ok)

    def test_rollout_must_be_observed_by_the_deployment_controller(self):
        not_yet = _status(found=False, dep=_rolled_out(generation=3, observed_generation=2))
        ok, _ = self._verify([not_yet] * 50, timeout=0.05)
        self.assertFalse(ok)

    def test_surplus_old_replicas_still_terminating_is_unhealthy(self):
        ok, _ = self._verify([_status(found=False, dep=_rolled_out(replicas=2))] * 50, timeout=0.05)
        self.assertFalse(ok)

    def test_waits_until_rollout_completes(self):
        seq = [_status(found=False, dep=_rolled_out(ready=0)),
               _status(found=False, dep=_rolled_out(ready=0)),
               _status(found=False, dep=_rolled_out())]
        with mock.patch("requests.get", side_effect=seq) as get:
            ok = self.executor.verify_remediation_health(POD, "RESTART_POD", NS, "cartservice", timeout=5.0, interval=0.0)
        self.assertTrue(ok)
        self.assertEqual(get.call_count, 3)

    def test_controller_unreachable_is_unhealthy(self):
        with mock.patch("requests.get", side_effect=requests.ConnectionError("refused")):
            ok = self.executor.verify_remediation_health(POD, "RESTART_POD", NS, "cartservice", timeout=0.05, interval=0.0)
        self.assertFalse(ok)

    def test_controller_error_status_is_unhealthy(self):
        bad = mock.Mock(status_code=500)
        bad.json.return_value = {"status": "error"}
        ok, _ = self._verify([bad] * 50, timeout=0.05)
        self.assertFalse(ok)

    def test_quarantine_requires_policy_and_label(self):
        ok, _ = self._verify([_status(quarantined=True)], action="CILIUM_QUARANTINE_EBPF", workload=None)
        self.assertTrue(ok)
        bad, _ = self._verify([_status(quarantined=False)] * 50, action="CILIUM_QUARANTINE_EBPF", workload=None, timeout=0.05)
        self.assertFalse(bad)

    def test_unquarantine_requires_not_quarantined(self):
        ok, _ = self._verify([_status(quarantined=False)], action="UNQUARANTINE_POD", workload=None)
        self.assertTrue(ok)
        bad, _ = self._verify([_status(quarantined=True)] * 50, action="UNQUARANTINE_POD", workload=None, timeout=0.05)
        self.assertFalse(bad)

    def test_scale_needs_every_desired_replica_ready(self):
        ok, _ = self._verify([_status(dep=_rolled_out(desired=3))], action="SCALE_DEPLOYMENT")
        self.assertTrue(ok)
        bad, _ = self._verify([_status(dep=_rolled_out(desired=3, ready=2))] * 50, action="SCALE_DEPLOYMENT", timeout=0.05)
        self.assertFalse(bad)

    def test_bare_pod_restart_needs_a_running_ready_pod(self):
        ok, _ = self._verify([_status(found=True, ready=True)], workload=None)
        self.assertTrue(ok)
        bad, _ = self._verify([_status(found=True, ready=False)] * 50, workload=None, timeout=0.05)
        self.assertFalse(bad)


class TestWebhookAutoRemediationFlag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from src.brain import main as brain_main

        cls.brain = brain_main
        cls.client = TestClient(brain_main.app)

    def _alert(self):
        return {"status": "firing", "alerts": [{"status": "firing", "labels": {
            "alertname": "AegisHighPodCPU", "pod": POD, "namespace": NS}, "annotations": {}}]}

    def test_webhook_only_diagnoses_by_default(self):
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "false"}), mock.patch.object(
            self.brain.diagnostic_engine, "diagnose_incident", return_value={"problem_type": "X"}
        ), mock.patch.object(self.brain, "process_alert") as pa:
            resp = self.client.post("/api/v1/alerts/webhook", json=self._alert())
        self.assertEqual(resp.status_code, 200)
        pa.assert_not_called()

    def test_webhook_acts_when_auto_remediate_enabled(self):
        fake = {"verdict": {"problem_type": "OPERATIONAL_BUG"}, "decision": {}, "execution": {},
                "verified": True, "escalated": False, "escalation": None}
        with mock.patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true"}), mock.patch.object(
            self.brain, "process_alert", return_value=fake
        ) as pa:
            resp = self.client.post("/api/v1/alerts/webhook", json=self._alert())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(pa.call_args.kwargs["namespace"], NS)
        self.assertTrue(resp.json()["diagnoses"][0]["accepted"])


if __name__ == "__main__":
    unittest.main()
