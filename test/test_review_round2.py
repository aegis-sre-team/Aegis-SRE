import support  # noqa: F401
import json
import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from src.brain import main as brain_main
from src.controller.executor import ActionExecutionResult, ActionExecutor
from src.guardrails.action_schema import GuardrailDecision, STATE_GUARDRAIL_APPROVED

POD = "cartservice-6f7d8c9b5-x2k4p"
NS = "online-boutique"


def decision(action="RESTART_POD", pod=POD, namespace=NS, **kw):
    return GuardrailDecision(
        approved=True, final_action=action, state=STATE_GUARDRAIL_APPROVED, reason="t", confidence=0.9,
        original_action=action, target_pod=pod, problem_type=kw.pop("problem_type", "OPERATIONAL_BUG"),
        mitre_technique=kw.pop("mitre_technique", None), namespace=namespace, **kw)


def _executor(dry_run, tmp=None):
    tmp = tmp or tempfile.mkdtemp(prefix="aegis_r2_")
    return ActionExecutor(namespace="default", dry_run_mode=dry_run,
                          audit_log_path=os.path.join(tmp, "audit.jsonl"), forensics_dir=tmp), tmp


# ----------------------------------------------------------------------------- R2-1
class TestControllerRouterIsGuarded(unittest.TestCase):
    VALID = {"approved": True, "final_action": "RESTART_POD", "state": STATE_GUARDRAIL_APPROVED, "reason": "r",
             "confidence": 0.9, "original_action": "RESTART_POD", "target_pod": POD,
             "problem_type": "OPERATIONAL_BUG", "namespace": NS}

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(brain_main.app)

    def setUp(self):
        p = mock.patch.dict(os.environ, {"AEGIS_INGEST_TOKEN": ""})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("AEGIS_ALLOWED_NAMESPACES", None)

    def test_valid_request_still_works(self):
        self.assertEqual(self.client.post("/api/v1/controller/execute", json=self.VALID).status_code, 200)

    def test_token_required_when_configured(self):
        with mock.patch.dict(os.environ, {"AEGIS_INGEST_TOKEN": "tok"}):
            self.assertEqual(self.client.post("/api/v1/controller/execute", json=self.VALID).status_code, 401)
            ok = self.client.post("/api/v1/controller/execute", json=self.VALID, headers={"X-Aegis-Token": "tok"})
            self.assertEqual(ok.status_code, 200)

    def test_path_traversal_and_bad_names_are_rejected(self):
        for field, value in (("target_pod", "../../x"), ("target_pod", "A B"), ("namespace", "bad ns")):
            body = dict(self.VALID, **{field: value})
            self.assertEqual(self.client.post("/api/v1/controller/execute", json=body).status_code, 400, (field, value))

    def test_namespace_policy_applies(self):
        body = dict(self.VALID, namespace="kube-system")
        resp = self.client.post("/api/v1/controller/execute", json=body)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("kube-system", resp.json()["detail"])


# ----------------------------------------------------------------------------- R2-2
class TestDashboardToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.dashboard import server

        cls.server = server
        cls.client = TestClient(server.app)

    def setUp(self):
        support.reset_restart_state()

    def _post(self, headers=None):
        ok = ActionExecutionResult(True, "RESTART_POD", POD, "done", "COMPLETED_DRY_RUN")
        with mock.patch.object(self.server.action_executor, "execute_decision", return_value=ok):
            resolve = self.client.post("/api/v1/escalation/resolve", headers=headers or {},
                                       json={"incident_id": "I", "target_pod": POD, "action": "RESTART_POD", "namespace": NS})
        chaos = self.client.post("/api/v1/chaos/trigger", headers=headers or {},
                                 json={"pod_name": "aegis-storefront-prod-1", "chaos_type": "http500"})
        return resolve.status_code, chaos.status_code

    def test_open_when_no_token_is_configured(self):
        with mock.patch.dict(os.environ, {"AEGIS_DASHBOARD_TOKEN": ""}):
            self.assertEqual(self._post(), (200, 200))

    def test_mutating_endpoints_need_the_token_when_configured(self):
        with mock.patch.dict(os.environ, {"AEGIS_DASHBOARD_TOKEN": "dash"}):
            self.assertEqual(self._post(), (401, 401))
            self.assertEqual(self._post({"X-Aegis-Token": "wrong"}), (401, 401))
            self.assertEqual(self._post({"X-Aegis-Token": "dash"}), (200, 200))
            self.assertEqual(self.client.get("/api/v1/telemetry/state").status_code, 200)  # read-only stays open


# ----------------------------------------------------------------------------- R2-3
class TestIncidentRequestValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(brain_main.app)

    def _post(self, path, body):
        with mock.patch.object(brain_main.diagnostic_engine, "diagnose_incident",
                               return_value={"problem_type": "X", "decision_object": None}), mock.patch.object(
            brain_main, "process_alert",
            return_value={"verdict": {}, "decision": None, "execution": None, "verified": False,
                          "escalated": True, "escalation": None, "dry_run": True},
        ) as pa:
            resp = self.client.post(path, json=body)
        return resp, pa

    def test_bad_values_are_rejected_before_anything_runs(self):
        bad = [{"pod_name": "..\\..\\somefile"}, {"pod_name": "a/../../b"}, {"pod_name": "UPPER"},
               {"pod_name": POD, "namespace": "bad ns"}, {"pod_name": POD, "alert_type": "x y"},
               {"pod_name": POD, "alert_type": "line\nbreak"}, {"pod_name": POD, "alert_type": "a" * 65}]
        for body in bad:
            for path in ("/api/v1/diagnose", "/api/v1/remediate"):
                resp, pa = self._post(path, body)
                self.assertEqual(resp.status_code, 422, (path, body))
                pa.assert_not_called()

    def test_valid_and_default_requests_pass(self):
        self.assertEqual(self._post("/api/v1/diagnose", {})[0].status_code, 200)
        ok = {"pod_name": POD, "namespace": NS, "alert_type": "falco_shell_spawn"}
        self.assertEqual(self._post("/api/v1/diagnose", ok)[0].status_code, 200)


# ----------------------------------------------------------------------------- R2-4
class TestLiveNeedsAnExplicitNamespace(unittest.TestCase):
    def test_live_decision_without_namespace_is_refused_without_calling_anything(self):
        ex, _ = _executor(dry_run=False)
        with mock.patch("requests.post") as post, mock.patch("subprocess.run") as run:
            result = ex.execute_decision(decision(namespace=None))
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, "FAILED_NO_NAMESPACE")
        post.assert_not_called()
        run.assert_not_called()

    def test_escalate_needs_no_namespace_even_live(self):
        ex, _ = _executor(dry_run=False)
        self.assertTrue(ex.execute_decision(decision("ESCALATE", namespace=None)).success)

    def test_dry_run_still_works_without_a_namespace(self):
        ex, _ = _executor(dry_run=True)
        self.assertTrue(ex.execute_decision(decision(namespace=None)).success)


# ----------------------------------------------------------------------------- R2-5
class TestTerminatingPodIsNotHealthy(unittest.TestCase):
    def setUp(self):
        self.ex, _ = _executor(dry_run=False)

    def _healthy(self, **status):
        base = {"found": True, "phase": "Running", "ready": True, "quarantined": False}
        base.update(status)
        return self.ex._status_is_healthy(base, "RESTART_POD")

    def test_running_ready_bare_pod_is_healthy(self):
        self.assertTrue(self._healthy())

    def test_a_terminating_pod_does_not_count_even_if_it_still_looks_ready(self):
        self.assertFalse(self._healthy(terminating=True))


# ----------------------------------------------------------------------------- R2-6
class TestWorkloadKindAwareFallback(unittest.TestCase):
    def setUp(self):
        self.ex, _ = _executor(dry_run=False)
        p = mock.patch.dict(os.environ, {"AEGIS_ALLOW_KUBECTL_FALLBACK": "true"})
        p.start()
        self.addCleanup(p.stop)

    def _ref(self, owner_stdout):
        done = mock.Mock(returncode=0, stdout=owner_stdout, stderr="")
        with mock.patch("subprocess.run", return_value=done):
            return self.ex._resolve_workload_ref("pod-x", "ns")

    def test_replicaset_owner_resolves_to_its_deployment(self):
        self.assertEqual(self._ref("ReplicaSet cartservice-6f7d8c9b5"), "deployment/cartservice")

    def test_statefulset_and_daemonset_keep_their_own_names(self):
        self.assertEqual(self._ref("StatefulSet my-db"), "statefulset/my-db")
        self.assertEqual(self._ref("DaemonSet node-exporter"), "daemonset/node-exporter")

    def test_restart_command_targets_the_resolved_kind(self):
        owner = mock.Mock(returncode=0, stdout="StatefulSet my-db", stderr="")
        restart = mock.Mock(returncode=0, stdout="statefulset.apps/my-db restarted", stderr="")
        with mock.patch("subprocess.run", side_effect=[owner, restart]) as run, mock.patch.object(
            self.ex, "verify_remediation_health", return_value=True
        ):
            result = self.ex.restart_pod("my-db-0", namespace=NS)
        self.assertTrue(result.success)
        cmd = run.call_args_list[1].args[0]
        self.assertIn("statefulset/my-db", cmd)
        self.assertNotIn("deployment/my", cmd)


# ----------------------------------------------------------------------------- R2-7
class TestDryRunDoesNotClaimVerification(unittest.TestCase):
    def test_dry_run_results_are_marked_and_unverified_in_every_record(self):
        ex, tmp = _executor(dry_run=True)
        for action in ("RESTART_POD", "SCALE_DEPLOYMENT"):
            result = ex.execute_decision(decision(action))
            self.assertNotIn("PASSED", result.details)
            self.assertIn("dry run", result.details.lower())
            as_dict = result.to_dict()
            self.assertTrue(as_dict["dry_run"])
            self.assertIsNone(as_dict["health_verified"])
        last = json.loads(open(os.path.join(tmp, "audit.jsonl"), encoding="utf-8").read().strip().splitlines()[-1])
        self.assertIsNone(last["health_verified"])
        self.assertTrue(last["dry_run"])

    def test_live_results_keep_their_verified_flag(self):
        ok = ActionExecutionResult(True, "RESTART_POD", POD, "done", "COMPLETED_GO_K8S_CLUSTER", health_verified=True)
        self.assertTrue(ok.to_dict()["health_verified"])
        self.assertFalse(ok.to_dict()["dry_run"])


# ----------------------------------------------------------------------------- R2-9
class TestQuarantineRecordScope(unittest.TestCase):
    def setUp(self):
        support.reset_quarantine_state()
        self.ex, _ = _executor(dry_run=False)

    def _active(self, namespace):
        from src.db.database import SessionLocal
        from src.db.models import QuarantineRecord

        with SessionLocal() as s:
            rec = s.query(QuarantineRecord).filter_by(target_pod=f"{namespace}/web-abc-xyz12").first()
        return None if rec is None else rec.active

    def test_same_pod_name_in_two_namespaces_has_independent_records(self):
        self.ex._record_quarantine_db("web-abc-xyz12", "ns-a", active=True)
        self.ex._record_quarantine_db("web-abc-xyz12", "ns-b", active=True)
        self.ex._record_quarantine_db("web-abc-xyz12", "ns-b", active=False)
        self.assertTrue(self._active("ns-a"))
        self.assertFalse(self._active("ns-b"))

    def test_dry_run_quarantine_records_nothing_because_nothing_was_isolated(self):
        ex, _ = _executor(dry_run=True)
        ex.execute_decision(decision("CILIUM_QUARANTINE_EBPF", pod="web-abc-xyz12", namespace="ns-a",
                                     problem_type="SECURITY_ATTACK"))
        self.assertIsNone(self._active("ns-a"))


if __name__ == "__main__":
    unittest.main()
