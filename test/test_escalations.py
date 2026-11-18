import support  # noqa: F401
import os
import tempfile
import unittest
from unittest import mock

from src.brain.remediation import process_alert
from src.db import database
from src.db.escalations import list_open_escalations, mark_escalated, resolve_escalation_record
from src.db.models import IncidentRecord
from src.guardrails.action_schema import GuardrailDecision, STATE_ESCALATE_HUMAN

UI_KEYS = {"incident_id", "target_pod", "problem_type", "confidence", "reason", "mitre_technique", "timestamp"}


def _verdict(incident_id="INC-ESC-1", pod="cartservice-6f7d8c9b5-x2k4p", problem="OPERATIONAL_BUG", **extra):
    v = {"incident_id": incident_id, "target_pod": pod, "problem_type": problem, "threat_level": "HIGH",
         "recommended_action": "RESTART_POD", "confidence": 0.9, "root_cause": "it is broken"}
    v.update(extra)
    return v


class _DbCase(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        database.configure_database("sqlite:///" + os.path.join(self._dir.name, "esc.db").replace("\\", "/"))
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(support.restore_default_database)

    def _rows(self, incident_id):
        with database.SessionLocal() as s:
            return s.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id).all()


class TestEscalationStore(_DbCase):
    def test_mark_escalated_inserts_when_the_incident_was_never_persisted(self):
        # The fail-closed SENSOR_DARK path never persists its verdict, so the upsert must create the row.
        v = _verdict("INC-DARK-1", problem="SENSOR_DARK", recommended_action="ESCALATE", confidence=0.0)
        self.assertTrue(mark_escalated(v, "sensors are dark"))
        rows = self._rows("INC-DARK-1")
        self.assertEqual(1, len(rows))
        self.assertEqual("ESCALATED", rows[0].status)
        self.assertEqual("sensors are dark", rows[0].guardrail_reason)

    def test_mark_escalated_updates_existing_open_row(self):
        with database.SessionLocal() as s:
            s.add(IncidentRecord(incident_id="INC-2", target_pod="p", problem_type="OPERATIONAL_BUG",
                                 recommended_action="RESTART_POD", final_action="RESTART_POD", status="OPEN"))
            s.commit()
        self.assertTrue(mark_escalated(_verdict("INC-2", pod="p"), "restart budget used up"))
        rows = self._rows("INC-2")
        self.assertEqual(1, len(rows))
        self.assertEqual(("ESCALATED", "ESCALATE", False), (rows[0].status, rows[0].final_action, rows[0].guardrail_approved))
        self.assertEqual("RESTART_POD", rows[0].recommended_action, "what the model proposed is kept")
        self.assertEqual("restart budget used up", rows[0].guardrail_reason)

    def test_mark_escalated_twice_keeps_one_row(self):
        mark_escalated(_verdict("INC-3"), "first")
        mark_escalated(_verdict("INC-3"), "second")
        rows = self._rows("INC-3")
        self.assertEqual(1, len(rows))
        self.assertEqual("second", rows[0].guardrail_reason)

    def test_list_open_escalations_shape_and_order(self):
        mark_escalated(_verdict("INC-A", pod="pod-a", mitre_technique="T1059"), "reason a")
        mark_escalated(_verdict("INC-B", pod="pod-b"), "reason b")
        with database.SessionLocal() as s:  # an incident that is merely OPEN must not be listed
            s.add(IncidentRecord(incident_id="INC-OPEN", target_pod="x", problem_type="X",
                                 recommended_action="RESTART_POD", final_action="RESTART_POD", status="OPEN"))
            s.commit()
        items = list_open_escalations()
        self.assertEqual(["INC-B", "INC-A"], [i["incident_id"] for i in items], "newest first, only ESCALATED")
        for item in items:
            self.assertEqual(UI_KEYS, set(item))
        self.assertEqual("reason a", items[1]["reason"])
        self.assertEqual("T1059", items[1]["mitre_technique"])
        self.assertEqual("pod-a", items[1]["target_pod"])
        self.assertIsInstance(items[1]["confidence"], float)

    def test_resolve_moves_it_out_of_the_list(self):
        mark_escalated(_verdict("INC-R"), "needs a human")
        self.assertTrue(resolve_escalation_record("INC-R"))
        self.assertEqual([], list_open_escalations())
        self.assertEqual("RESOLVED", self._rows("INC-R")[0].status)
        self.assertFalse(resolve_escalation_record("INC-R"), "already resolved")

    def test_resolve_unknown_id_returns_false(self):
        self.assertFalse(resolve_escalation_record("INC-NOPE"))

    def test_a_verdict_without_an_incident_id_is_refused_not_invented(self):
        self.assertFalse(mark_escalated({"target_pod": "p"}, "no id"))
        self.assertEqual([], list_open_escalations())

    def test_a_broken_database_never_raises(self):
        with mock.patch("src.db.database.SessionLocal", side_effect=RuntimeError("db down")):
            self.assertFalse(mark_escalated(_verdict("INC-X"), "x"))
            self.assertEqual([], list_open_escalations())
            self.assertFalse(resolve_escalation_record("INC-X"))


class _Engine:
    def __init__(self, decision):
        self.decision = decision

    def diagnose_incident(self, pod_name, alert_type, namespace=None, **kw):
        return {"incident_id": "INC-PA-1", "target_pod": pod_name, "namespace": namespace,
                "problem_type": self.decision.problem_type, "root_cause": "rc",
                "recommended_action": self.decision.original_action, "decision_object": self.decision}


class _Notifier:
    def dispatch_escalation(self, decision, verdict):
        return {"webhook_status": "SKIPPED_NO_URL"}


class TestProcessAlertRecordsEscalations(_DbCase):
    def test_process_alert_records_escalation(self):
        pod = "chaos-restart-storm-abc-xyz"
        decision = GuardrailDecision(
            approved=False, final_action="ESCALATE", state=STATE_ESCALATE_HUMAN,
            reason="Pod exceeded restart frequency cap. Escalated to prevent restart loop.", confidence=0.9,
            original_action="RESTART_POD", target_pod=pod, problem_type="OPERATIONAL_BUG", namespace="aegis-chaos")
        out = process_alert(_Engine(decision), mock.Mock(dry_run_mode=True), _Notifier(), pod, "AegisPodCrashLooping",
                            namespace="aegis-chaos")
        self.assertTrue(out["escalated"])
        items = list_open_escalations()
        self.assertEqual(1, len(items))
        self.assertEqual(("INC-PA-1", pod), (items[0]["incident_id"], items[0]["target_pod"]))
        self.assertIn("restart frequency cap", items[0]["reason"])


if __name__ == "__main__":
    unittest.main()
