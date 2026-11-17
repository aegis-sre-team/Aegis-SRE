import support  # noqa: F401  (hermetic env; must precede src imports)
import sys
import os
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.db.database import configure_database
from src.guardrails import (
    GuardrailEngine,
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN,
    validate_controller_decision,
)


class TestGuardrailEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._db_path = os.path.join(cls._tmpdir.name, "guardrails_test.db")
        configure_database(f"sqlite:///{cls._db_path}")

    @classmethod
    def tearDownClass(cls):
        try:
            from src.db.database import engine

            engine.dispose()
        except Exception:
            pass
        cls._tmpdir.cleanup()
        support.restore_default_database()

    def setUp(self):
        from src.db.database import SessionLocal

        self.engine = GuardrailEngine(
            min_confidence_threshold=0.70,
            max_restarts_per_hour=3,
            session_factory=SessionLocal,
            persist=True,
            also_jsonl=False,
        )
        self.engine.reset_rate_limits()

    def test_approve_valid_operational_bug(self):
        verdict = {
            "target_pod": "checkout-service-prod",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "RESTART_POD",
            "confidence": 0.85,
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        self.assertEqual(decision.final_action, "RESTART_POD")
        self.assertEqual(decision.state, STATE_GUARDRAIL_APPROVED)
        self.assertTrue(decision.schema_valid)

    def test_approve_valid_security_attack(self):
        verdict = {
            "target_pod": "payment-service-prod",
            "problem_type": "SECURITY_ATTACK",
            "recommended_action": "CILIUM_QUARANTINE_EBPF",
            "confidence": 0.92,
            "mitre_technique": "T1059",
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        self.assertEqual(decision.final_action, "CILIUM_QUARANTINE_EBPF")
        self.assertEqual(decision.state, STATE_GUARDRAIL_APPROVED)

    def test_reject_catastrophic_blocklist_action(self):
        verdict = {
            "target_pod": "database-pod",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "DELETE_NAMESPACE",
            "confidence": 0.99,
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertFalse(decision.approved)
        self.assertEqual(decision.final_action, "ESCALATE")
        self.assertEqual(decision.state, STATE_ACTION_REJECTED)
        self.assertIn("blocked by catastrophic safety filter", decision.reason)

    def test_escalate_low_confidence(self):
        verdict = {
            "target_pod": "frontend-service",
            "problem_type": "UNKNOWN",
            "recommended_action": "RESTART_POD",
            "confidence": 0.45,
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertFalse(decision.approved)
        self.assertEqual(decision.final_action, "ESCALATE")
        self.assertEqual(decision.state, STATE_ESCALATE_HUMAN)
        self.assertIn("below minimum threshold", decision.reason)

    def test_rate_limiter_loop_prevention(self):
        verdict = {
            "target_pod": "flaky-service",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "RESTART_POD",
            "confidence": 0.88,
        }
        for i in range(3):
            d = self.engine.validate_verdict(verdict)
            self.assertTrue(d.approved, f"Restart #{i+1} should be approved")

        d4 = self.engine.validate_verdict(verdict)
        self.assertFalse(d4.approved)
        self.assertEqual(d4.final_action, "ESCALATE")
        self.assertEqual(d4.state, STATE_ACTION_REJECTED)
        self.assertTrue(d4.rate_limit_exceeded)
        self.assertIn("exceeded restart frequency cap", d4.reason)

    def test_rate_limit_survives_process_restart(self):
        """DB-backed restart history must survive a new GuardrailEngine instance."""
        from src.db.database import SessionLocal
        from src.db.models import GuardrailDecisionRecord

        pod = "persistent-flaky-pod"
        verdict = {
            "target_pod": pod,
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "RESTART_POD",
            "confidence": 0.90,
        }
        for _ in range(3):
            self.assertTrue(self.engine.validate_verdict(verdict).approved)

        # Simulate process restart: new engine, same DB
        engine2 = GuardrailEngine(
            min_confidence_threshold=0.70,
            max_restarts_per_hour=3,
            session_factory=SessionLocal,
            persist=True,
            also_jsonl=False,
        )
        d4 = engine2.validate_verdict(verdict)
        self.assertFalse(d4.approved)
        self.assertTrue(d4.rate_limit_exceeded)

        with SessionLocal() as session:
            audits = (
                session.query(GuardrailDecisionRecord)
                .filter(GuardrailDecisionRecord.target_pod == pod)
                .all()
            )
            self.assertGreaterEqual(len(audits), 4)

    def test_schema_validation_rejects_missing_fields(self):
        decision = self.engine.validate_verdict({"confidence": 0.99})
        self.assertFalse(decision.approved)
        self.assertFalse(decision.schema_valid)
        self.assertEqual(decision.state, STATE_ACTION_REJECTED)
        self.assertIn("schema validation", decision.reason.lower())

    def test_controller_schema_before_execute(self):
        ok, err = validate_controller_decision(
            {
                "approved": True,
                "final_action": "RESTART_POD",
                "state": STATE_GUARDRAIL_APPROVED,
                "reason": "ok",
                "confidence": 0.9,
                "original_action": "RESTART_POD",
                "target_pod": "x",
                "problem_type": "OPERATIONAL_BUG",
            }
        )
        self.assertIsNotNone(ok)
        self.assertIsNone(err)

        bad, err2 = validate_controller_decision(
            {
                "approved": True,
                "final_action": "DELETE_NAMESPACE",
                "state": STATE_GUARDRAIL_APPROVED,
                "reason": "bad",
                "confidence": 0.9,
                "original_action": "DELETE_NAMESPACE",
                "target_pod": "x",
                "problem_type": "OPERATIONAL_BUG",
            }
        )
        self.assertIsNone(bad)
        self.assertIn("ALLOWED_ACTIONS", err2)

    def test_security_attack_restart_override(self):
        verdict = {
            "target_pod": "compromised-pod",
            "problem_type": "SECURITY_ATTACK",
            "recommended_action": "RESTART_POD",
            "confidence": 0.88,
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        self.assertEqual(decision.final_action, "CILIUM_QUARANTINE_EBPF")
        self.assertIn("Overrode RESTART_POD", decision.reason)

    # --- namespace safety (Phase 5) -------------------------------------------------
    def _verdict(self, action="RESTART_POD", namespace="online-boutique", **extra):
        v = {
            "target_pod": "cartservice-6f7d8c9b5-x2k4p",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": action,
            "confidence": 0.9,
            "namespace": namespace,
        }
        v.update(extra)
        return v

    def test_namespace_propagates_to_decision(self):
        decision = self.engine.validate_verdict(self._verdict())
        self.assertTrue(decision.approved)
        self.assertEqual(decision.namespace, "online-boutique")

    def test_decision_namespace_is_none_when_verdict_has_none(self):
        v = self._verdict()
        v.pop("namespace")
        decision = self.engine.validate_verdict(v)
        self.assertTrue(decision.approved)
        self.assertIsNone(decision.namespace)

    def test_protected_namespace_rejected_for_every_mutating_action(self):
        from src.guardrails import PROTECTED_NAMESPACES

        self.assertEqual(
            PROTECTED_NAMESPACES,
            {"kube-system", "kube-public", "kube-node-lease", "aegis-system", "monitoring", "cilium-secrets"},
        )
        for ns in sorted(PROTECTED_NAMESPACES):
            for action in ("RESTART_POD", "SCALE_DEPLOYMENT", "CILIUM_QUARANTINE_EBPF", "UNQUARANTINE_POD"):
                with self.subTest(namespace=ns, action=action):
                    d = self.engine.validate_verdict(self._verdict(action=action, namespace=ns))
                    self.assertFalse(d.approved)
                    self.assertEqual(d.final_action, "ESCALATE")
                    self.assertEqual(d.state, STATE_ACTION_REJECTED)
                    self.assertIn(ns, d.reason)
                    self.assertEqual(d.namespace, ns)

    def test_protected_namespace_does_not_consume_restart_quota(self):
        for _ in range(5):
            self.engine.validate_verdict(self._verdict(namespace="kube-system"))
        d = self.engine.validate_verdict(self._verdict())
        self.assertTrue(d.approved)

    def test_escalate_is_allowed_in_protected_namespace(self):
        d = self.engine.validate_verdict(self._verdict(action="ESCALATE", namespace="kube-system"))
        self.assertTrue(d.approved)
        self.assertEqual(d.final_action, "ESCALATE")

    def test_allowlist_env_blocks_other_namespaces(self):
        from unittest import mock

        with mock.patch.dict(os.environ, {"AEGIS_ALLOWED_NAMESPACES": "online-boutique, aegis-chaos"}):
            ok = self.engine.validate_verdict(self._verdict(namespace="aegis-chaos"))
            blocked = self.engine.validate_verdict(self._verdict(namespace="default"))
        self.assertTrue(ok.approved)
        self.assertFalse(blocked.approved)
        self.assertEqual(blocked.state, STATE_ACTION_REJECTED)
        self.assertIn("allowed", blocked.reason.lower())

    def test_controller_schema_carries_namespace(self):
        parsed, err = validate_controller_decision(
            {
                "approved": True,
                "final_action": "RESTART_POD",
                "state": STATE_GUARDRAIL_APPROVED,
                "reason": "ok",
                "confidence": 0.9,
                "original_action": "RESTART_POD",
                "target_pod": "x",
                "problem_type": "OPERATIONAL_BUG",
                "namespace": "online-boutique",
            }
        )
        self.assertIsNone(err)
        self.assertEqual(parsed.namespace, "online-boutique")

    # --- hardening: workload-keyed budget, confidence, autonomous release ----------------------
    def test_workload_key_strips_replicaset_and_statefulset_suffixes(self):
        from src.guardrails.action_schema import workload_key

        self.assertEqual(workload_key("online-boutique", "cartservice-6f7d8c9b5-x2k4p"), "online-boutique/cartservice")
        self.assertEqual(workload_key("db", "redis-0"), "db/redis")
        self.assertEqual(workload_key(None, "lonely"), "-/lonely")

    def test_restart_budget_is_shared_across_replacement_pods(self):
        decisions = [
            self.engine.validate_verdict(self._verdict(target_pod=f"cartservice-6f7d8c9b5-{suffix}"))
            for suffix in ("aaaaa", "bbbbb", "ccccc", "ddddd")
        ]
        self.assertEqual([d.approved for d in decisions], [True, True, True, False])
        self.assertTrue(decisions[3].rate_limit_exceeded)

    def test_restart_budget_not_shared_across_namespaces(self):
        for suffix in ("aaaaa", "bbbbb", "ccccc"):
            self.engine.validate_verdict(self._verdict(target_pod=f"cartservice-6f7d8c9b5-{suffix}"))
        other = self.engine.validate_verdict(
            self._verdict(target_pod="cartservice-6f7d8c9b5-zzzzz", namespace="aegis-chaos"))
        self.assertTrue(other.approved)

    def test_restart_budget_holds_under_concurrency(self):
        import threading

        results = []

        def worker(i):
            results.append(self.engine.validate_verdict(self._verdict(target_pod=f"cartservice-6f7d8c9b5-p{i:04d}")))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for d in results if d.approved), 3)

    def test_missing_confidence_is_escalated_not_defaulted_upward(self):
        v = self._verdict()
        v.pop("confidence")
        d = self.engine.validate_verdict(v)
        self.assertFalse(d.approved)
        self.assertEqual(d.final_action, "ESCALATE")
        self.assertEqual(d.state, STATE_ESCALATE_HUMAN)

    def test_garbage_or_out_of_range_confidence_is_rejected(self):
        for bad in (1.5, -0.1, "high", [0.9]):
            with self.subTest(confidence=bad):
                d = self.engine.validate_verdict(self._verdict(confidence=bad))
                self.assertFalse(d.approved)
                self.assertFalse(d.schema_valid)
                self.assertEqual(d.final_action, "ESCALATE")

    def test_autonomous_unquarantine_is_escalated_to_a_human(self):
        d = self.engine.validate_verdict(self._verdict(action="UNQUARANTINE_POD"))
        self.assertFalse(d.approved)
        self.assertEqual(d.state, STATE_ACTION_REJECTED)
        self.assertIn("human", d.reason.lower())

    def test_namespace_violation_is_public(self):
        from src.guardrails import GuardrailEngine as G

        self.assertTrue(G.namespace_violation("kube-system", "RESTART_POD"))
        self.assertIsNone(G.namespace_violation("online-boutique", "RESTART_POD"))


if __name__ == "__main__":
    unittest.main()
