import support  # noqa: F401
import json
import os
import tempfile
import unittest
from unittest import mock

import requests

from src.controller.executor import ActionExecutor
from src.guardrails.action_schema import GuardrailDecision, STATE_GUARDRAIL_APPROVED

CONTROLLER_URL = "http://aegis-controller.aegis-system.svc:8080/api/v1/reconcile"


def _decision(action="RESTART_POD", pod="cartservice-6f7d8c9b5-x2k4p", namespace="online-boutique", **kw):
    return GuardrailDecision(
        approved=True,
        final_action=action,
        state=STATE_GUARDRAIL_APPROVED,
        reason="test",
        confidence=0.9,
        original_action=action,
        target_pod=pod,
        problem_type=kw.pop("problem_type", "OPERATIONAL_BUG"),
        mitre_technique=kw.pop("mitre_technique", None),
        namespace=namespace,
        **kw,
    )


def _response(status=200, body=None):
    resp = mock.Mock()
    resp.status_code = status
    resp.json.return_value = body if body is not None else {}
    return resp


FORENSICS = {
    "captured_at": "2026-11-17T10:00:00Z",
    "pod": "cartservice-6f7d8c9b5-x2k4p",
    "namespace": "online-boutique",
    "phase": "Running",
    "node_name": "node-1",
    "pod_ip": "10.42.0.9",
    "labels": {"app": "cartservice"},
    "container_statuses": [{"name": "server", "image": "x", "ready": True, "restart_count": 0, "state": "running"}],
    "events": ["Normal Started container"],
    "logs": {"server": ["listening on :7070", "spawned /bin/sh"]},
    "process_list": "USER PID COMMAND\nroot 1 /app\nroot 77 /bin/sh -i",
    "errors": [],
}


class TestExecutorControllerDispatch(unittest.TestCase):
    def setUp(self):
        support.reset_restart_state()
        support.reset_quarantine_state()
        self.tmp = tempfile.mkdtemp(prefix="aegis_exec_")
        self.executor = ActionExecutor(
            namespace="default",
            audit_log_path=os.path.join(self.tmp, "audit.jsonl"),
            dry_run_mode=False,
            forensics_dir=self.tmp,
        )
        env = {"GO_CONTROLLER_URL": CONTROLLER_URL, "GO_CONTROLLER_TOKEN": "s3cret"}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("AEGIS_ALLOW_KUBECTL_FALLBACK", None)

    def test_live_dispatch_sends_namespace_and_token(self):
        ok = _response(200, {"status": "success", "mode": "k8s_cluster", "message": "rollout restart triggered"})
        with mock.patch("requests.post", return_value=ok) as post, mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            result = self.executor.execute_decision(_decision())
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, "COMPLETED_GO_K8S_CLUSTER")
        args, kwargs = post.call_args
        self.assertEqual(args[0], CONTROLLER_URL)
        self.assertEqual(kwargs["json"]["namespace"], "online-boutique")
        self.assertEqual(kwargs["json"]["target_pod"], "cartservice-6f7d8c9b5-x2k4p")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer s3cret")

    def test_live_unreachable_controller_fails_closed(self):
        with mock.patch("requests.post", side_effect=requests.ConnectionError("refused")), mock.patch(
            "subprocess.run"
        ) as run, mock.patch("subprocess.Popen") as popen:
            result = self.executor.execute_decision(_decision())
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, "FAILED_CONTROLLER_UNREACHABLE")
        run.assert_not_called()
        popen.assert_not_called()

    def test_kubectl_fallback_only_when_opted_in(self):
        completed = mock.Mock(returncode=0, stdout="deployment.apps/cartservice restarted", stderr="")
        with mock.patch.dict(os.environ, {"AEGIS_ALLOW_KUBECTL_FALLBACK": "true"}), mock.patch(
            "requests.post", side_effect=requests.ConnectionError("refused")
        ), mock.patch("subprocess.run", return_value=completed) as run, mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            result = self.executor.execute_decision(_decision())
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, "COMPLETED_LIVE")
        self.assertTrue(run.called)
        cmd = run.call_args_list[0].args[0]
        self.assertIn("online-boutique", cmd)  # decision namespace, not the executor default

    def test_escalate_never_needs_the_controller(self):
        with mock.patch("requests.post", side_effect=requests.ConnectionError("refused")) as post:
            result = self.executor.execute_decision(_decision("ESCALATE"))
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, "ESCALATED_HUMAN")
        post.assert_not_called()

    def test_controller_dry_run_reply_is_a_failure_when_the_brain_is_live(self):
        dry = _response(200, {"status": "success", "mode": "dry_run", "message": "[DRY_RUN] would execute"})
        for action in ("RESTART_POD", "CILIUM_QUARANTINE_EBPF"):
            with mock.patch("requests.post", return_value=dry), mock.patch.object(
                self.executor, "verify_remediation_health", return_value=True
            ) as verify:
                result = self.executor.execute_decision(_decision(action, problem_type="SECURITY_ATTACK"))
            self.assertFalse(result.success, action)
            self.assertEqual(result.status_code, "FAILED_CONTROLLER_DRY_RUN")
            self.assertIn("DRY_RUN", result.details)
            self.assertIsNone(result.forensics_file)
            verify.assert_not_called()
        from src.db.database import SessionLocal
        from src.db.models import QuarantineRecord

        with SessionLocal() as s:
            rec = s.query(QuarantineRecord).filter_by(target_pod="online-boutique/cartservice-6f7d8c9b5-x2k4p").first()
        self.assertTrue(rec is None or not rec.active, "a dry-run controller must not create a quarantine record")

    def test_second_quarantine_does_not_overwrite_the_first_forensics(self):
        first = dict(FORENSICS, events=["FIRST: before isolation"])
        second = dict(FORENSICS, events=["SECOND: after isolation"])
        paths = []
        for forensics in (first, second):
            body = {"status": "success", "mode": "k8s_cluster", "message": "q", "policy_name": "p", "forensics": forensics}
            with mock.patch("requests.post", return_value=_response(200, body)), mock.patch.object(
                self.executor, "verify_remediation_health", return_value=True
            ):
                paths.append(self.executor.execute_decision(
                    _decision("CILIUM_QUARANTINE_EBPF", problem_type="SECURITY_ATTACK")).forensics_file)
        self.assertNotEqual(paths[0], paths[1])
        self.assertTrue(paths[0].endswith("forensics_cartservice-6f7d8c9b5-x2k4p.json"))
        self.assertEqual(json.load(open(paths[0], encoding="utf-8"))["events"], ["FIRST: before isolation"])
        self.assertEqual(json.load(open(paths[1], encoding="utf-8"))["events"], ["SECOND: after isolation"])

    def test_missing_forensics_does_not_clobber_an_existing_snapshot(self):
        real = {"status": "success", "mode": "k8s_cluster", "message": "q", "policy_name": "p", "forensics": FORENSICS}
        empty = {"status": "success", "mode": "k8s_cluster", "message": "already quarantined"}
        with mock.patch("requests.post", return_value=_response(200, real)), mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            first = self.executor.execute_decision(_decision("CILIUM_QUARANTINE_EBPF", problem_type="SECURITY_ATTACK"))
        before = open(first.forensics_file, encoding="utf-8").read()
        with mock.patch("requests.post", return_value=_response(200, empty)), mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            again = self.executor.execute_decision(_decision("CILIUM_QUARANTINE_EBPF", problem_type="SECURITY_ATTACK"))
        self.assertEqual(again.forensics_file, first.forensics_file)
        self.assertEqual(open(first.forensics_file, encoding="utf-8").read(), before)

    def test_not_found_from_controller_is_failure(self):
        nf = _response(404, {"status": "error", "error": "not found: pod online-boutique/x"})
        with mock.patch("requests.post", return_value=nf):
            result = self.executor.execute_decision(_decision())
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, "FAILED_CONTROLLER_NOT_FOUND")
        self.assertIn("not found", result.details)

    def test_controller_server_error_is_failure(self):
        boom = _response(500, {"status": "error", "error": "boom"})
        with mock.patch("requests.post", return_value=boom):
            result = self.executor.execute_decision(_decision())
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, "FAILED_CONTROLLER_500")

    def test_controller_rejection_403_is_failure(self):
        refused = _response(403, {"status": "error", "error": "namespace is protected"})
        with mock.patch("requests.post", return_value=refused):
            result = self.executor.execute_decision(_decision())
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, "FAILED_CONTROLLER_403")

    def test_quarantine_persists_controller_forensics_and_db_record(self):
        body = {"status": "success", "mode": "k8s_cluster", "message": "quarantined", "policy_name": "aegis-quarantine-x",
                "forensics": FORENSICS}
        with mock.patch("requests.post", return_value=_response(200, body)), mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            result = self.executor.execute_decision(
                _decision("CILIUM_QUARANTINE_EBPF", problem_type="SECURITY_ATTACK", mitre_technique="T1059")
            )
        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(result.forensics_file))
        saved = json.load(open(result.forensics_file, encoding="utf-8"))
        self.assertEqual(saved["target_pod"], "cartservice-6f7d8c9b5-x2k4p")
        self.assertEqual(saved["namespace"], "online-boutique")
        self.assertEqual(saved["data_source"], "cluster")
        self.assertEqual(saved["events"], ["Normal Started container"])
        self.assertIn("spawned /bin/sh", saved["logs"]["server"])
        self.assertEqual([p["pid"] for p in saved["process_tree"]], ["1", "77"])

        from src.db.database import SessionLocal
        from src.db.models import QuarantineRecord

        with SessionLocal() as s:
            rec = s.query(QuarantineRecord).filter_by(target_pod="online-boutique/cartservice-6f7d8c9b5-x2k4p").first()
        self.assertIsNotNone(rec)
        self.assertTrue(rec.active)

    def test_unquarantine_live_clears_db_record(self):
        self.executor._record_quarantine_db("cartservice-6f7d8c9b5-x2k4p", "online-boutique", active=True)
        ok = _response(200, {"status": "success", "mode": "k8s_cluster", "message": "released"})
        with mock.patch("requests.post", return_value=ok), mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            result = self.executor.execute_decision(_decision("UNQUARANTINE_POD"))
        self.assertTrue(result.success)
        from src.db.database import SessionLocal
        from src.db.models import QuarantineRecord

        with SessionLocal() as s:
            rec = s.query(QuarantineRecord).filter_by(target_pod="online-boutique/cartservice-6f7d8c9b5-x2k4p").first()
        self.assertFalse(rec.active)

    def test_missing_forensics_from_controller_is_reported_not_invented(self):
        body = {"status": "success", "mode": "k8s_cluster", "message": "quarantined"}  # no forensics key
        with mock.patch("requests.post", return_value=_response(200, body)), mock.patch.object(
            self.executor, "verify_remediation_health", return_value=True
        ):
            result = self.executor.execute_decision(_decision("CILIUM_QUARANTINE_EBPF", problem_type="SECURITY_ATTACK"))
        saved = json.load(open(result.forensics_file, encoding="utf-8"))
        self.assertEqual(saved["process_tree"], [])
        self.assertEqual(saved["data_source"], "none")
        self.assertTrue(saved["errors"])


class TestDryRunForensicsAreHonest(unittest.TestCase):
    def test_dry_run_forensics_contain_no_invented_processes(self):
        tmp = tempfile.mkdtemp(prefix="aegis_dry_")
        ex = ActionExecutor(namespace="aegis-chaos", audit_log_path=os.path.join(tmp, "a.jsonl"),
                            dry_run_mode=True, forensics_dir=tmp)
        res = ex.execute_decision(_decision("CILIUM_QUARANTINE_EBPF", namespace="aegis-chaos",
                                            problem_type="SECURITY_ATTACK", mitre_technique="T1059"))
        saved = json.load(open(res.forensics_file, encoding="utf-8"))
        self.assertEqual(saved["execution_mode"], "DRY_RUN_NO_CLUSTER_DATA")
        self.assertEqual(saved["data_source"], "none")
        self.assertEqual(saved["process_tree"], [])
        self.assertEqual(saved["simulated_process_tree"], [])
        self.assertEqual(saved["active_sockets"], [])
        self.assertEqual(saved["container_logs_snapshot"], [])
        self.assertEqual(saved["namespace"], "aegis-chaos")


if __name__ == "__main__":
    unittest.main()
