import unittest
import os
import json
from unittest.mock import patch
from src.brain.diagnostic_engine import DiagnosticEngine
from src.controller.executor import ActionExecutor
from src.guardrails.action_schema import STATE_GUARDRAIL_APPROVED

TEST_PIPELINE_AUDIT_LOG = "logs/test_pipeline_audit.jsonl"

class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        self.diagnostic_engine = DiagnosticEngine()
        self.executor = ActionExecutor(
            namespace="default",
            audit_log_path=TEST_PIPELINE_AUDIT_LOG,
            dry_run_mode=True
        )
        if os.path.exists(TEST_PIPELINE_AUDIT_LOG):
            os.remove(TEST_PIPELINE_AUDIT_LOG)

    def tearDown(self):
        if os.path.exists(TEST_PIPELINE_AUDIT_LOG):
            os.remove(TEST_PIPELINE_AUDIT_LOG)

    def _patch_sensors(self, falco_events=None):
        """Offline unit tests: honest empty metrics + optional Falco lines (no invented healthy defaults)."""
        metrics = {
            "total_requests": 100,
            "error_500_count": 25,
            "avg_latency_ms": 40.0,
            "memory_mb": 200.0,
            "memory_limit_mb": 512.0,
            "memory_pct": 39.0,
            "cpu_usage_pct": 30.0,
            "sensor_ok": True,
            "source": "test-mock",
        }
        return (
            patch.object(self.diagnostic_engine.collector, "check_sensors", return_value={
                "prometheus": {"ok": True, "detail": "mock"},
                "loki": {"ok": True, "detail": "mock"},
                "falco_via_loki": {"ok": True, "detail": "mock"},
            }),
            patch.object(self.diagnostic_engine.collector, "any_critical_dark", return_value=False),
            patch.object(self.diagnostic_engine.collector, "fetch_prometheus_metrics", return_value=metrics),
            patch.object(self.diagnostic_engine.collector, "fetch_loki_logs", return_value=["[ERROR] database connection failure"]),
            patch.object(self.diagnostic_engine.collector, "fetch_falco_alerts", return_value=falco_events or []),
        )

    def test_e2e_operational_bug_remediation(self):
        """Tests end-to-end Bug Path: Alert -> Diagnosis -> Guardrail -> RESTART_POD Execution."""
        patches = self._patch_sensors()
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        verdict = self.diagnostic_engine.diagnose_incident(
            pod_name="storefront-app-pod-123",
            alert_type="HTTP_500_SPIKE"
        )
        self.assertIn("guardrail_validation", verdict)
        self.assertTrue(verdict["guardrail_validation"]["approved"])
        self.assertEqual(verdict["guardrail_validation"]["final_action"], "RESTART_POD")

        # 2. Run Controller Execution
        decision = verdict["decision_object"]
        exec_result = self.executor.execute_decision(decision)
        self.assertTrue(exec_result.success)
        self.assertEqual(exec_result.action, "RESTART_POD")
        self.assertEqual(exec_result.status_code, "COMPLETED_DRY_RUN")

    def test_e2e_security_attack_remediation(self):
        """Tests end-to-end Attack Path: Falco Alert -> Diagnosis -> Guardrail Override -> CILIUM_QUARANTINE_EBPF Execution."""
        falco = [
            "[SECURITY_ALERT] Falco eBPF: Notice Shell spawned in container MITRE:T1059"
        ]
        patches = self._patch_sensors(falco_events=falco)
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        verdict = self.diagnostic_engine.diagnose_incident(
            pod_name="compromised-cart-service",
            alert_type="falco_shell_spawn"
        )
        self.assertIn("guardrail_validation", verdict)
        self.assertTrue(verdict["guardrail_validation"]["approved"])
        self.assertEqual(verdict["guardrail_validation"]["final_action"], "CILIUM_QUARANTINE_EBPF")
        self.assertEqual(verdict["problem_type"], "SECURITY_ATTACK")

        # 2. Run Controller Execution
        decision = verdict["decision_object"]
        exec_result = self.executor.execute_decision(decision)
        self.assertTrue(exec_result.success)
        self.assertEqual(exec_result.action, "CILIUM_QUARANTINE_EBPF")
        self.assertIsNotNone(exec_result.policy_applied)
        self.assertEqual(exec_result.policy_applied["kind"], "CiliumNetworkPolicy")
        self.assertEqual(exec_result.policy_applied["spec"]["ingress"], [])
        self.assertEqual(exec_result.policy_applied["spec"]["egress"], [])


if __name__ == "__main__":
    unittest.main()
