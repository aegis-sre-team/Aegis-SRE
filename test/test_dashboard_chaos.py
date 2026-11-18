import support  # noqa: F401  (hermetic env; must precede src imports)
import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from src.dashboard import server
import requests

from src.dashboard.chaos_client import ChaosClient, ChaosError
from src.db import database
from src.db.escalations import list_open_escalations, mark_escalated
from src.db.models import AuditLogRecord

RUNNING ={"id": "cpu-spike", "deployment": "chaos-cpu-spike", "installed": True, "replicas": 1, "ready": 1}
STOPPED = {"id": "oom", "deployment": "chaos-oom", "installed": True, "replicas": 0, "ready": 0}


class _Base(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.app)
        self._dir = tempfile.TemporaryDirectory()
        database.configure_database("sqlite:///" + os.path.join(self._dir.name, "dash.db").replace("\\", "/"))
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(support.restore_default_database)

    def live(self):
        p = mock.patch.object(server, "current_data_source", return_value="live")
        p.start()
        self.addCleanup(p.stop)


class TestChaosRoutes(_Base):
    def test_chaos_routes_return_409_in_demo_mode(self):
        with mock.patch.object(server.chaos_client, "list") as lst, mock.patch.object(server.chaos_client, "set") as st:
            for resp in (
                self.client.get("/api/v1/chaos/scenarios"),
                self.client.post("/api/v1/chaos/scenarios/cpu-spike/start"),
                self.client.post("/api/v1/chaos/scenarios/cpu-spike/stop"),
                self.client.post("/api/v1/chaos/stop-all"),
            ):
                self.assertEqual(409, resp.status_code)
                self.assertIn("live cluster", resp.json()["detail"])
            lst.assert_not_called()
            st.assert_not_called()

    def test_list_returns_the_controllers_scenarios(self):
        self.live()
        with mock.patch.object(server.chaos_client, "list", return_value=[RUNNING, STOPPED]):
            resp = self.client.get("/api/v1/chaos/scenarios")
        self.assertEqual(200, resp.status_code)
        self.assertEqual([RUNNING, STOPPED], resp.json()["scenarios"])

    def test_start_passes_scenario_and_ttl_to_the_controller(self):
        self.live()
        with mock.patch.object(server.chaos_client, "set", return_value=RUNNING) as st:
            resp = self.client.post("/api/v1/chaos/scenarios/cpu-spike/start", json={"ttl_minutes": 10})
            self.assertEqual(200, resp.status_code)
            st.assert_called_once_with("cpu-spike", "on", 10)
            self.assertEqual(RUNNING, resp.json())
        with mock.patch.object(server.chaos_client, "set", return_value=RUNNING) as st:
            self.assertEqual(200, self.client.post("/api/v1/chaos/scenarios/cpu-spike/start").status_code)
            st.assert_called_once_with("cpu-spike", "on", None)

    def test_stop_passes_off_to_the_controller(self):
        self.live()
        with mock.patch.object(server.chaos_client, "set", return_value=STOPPED) as st:
            self.assertEqual(200, self.client.post("/api/v1/chaos/scenarios/oom/stop").status_code)
            st.assert_called_once_with("oom", "off")

    def test_bad_scenario_id_is_rejected_before_any_call(self):
        self.live()
        with mock.patch.object(server.chaos_client, "set") as st:
            for bad in ("UPPER", "a_b", "x" * 40):
                for verb in ("start", "stop"):
                    resp = self.client.post(f"/api/v1/chaos/scenarios/{bad}/{verb}")
                    self.assertEqual(400, resp.status_code, f"{bad}/{verb}")
            st.assert_not_called()

    def test_controller_unreachable_returns_502_with_message(self):
        self.live()
        with mock.patch.object(server.chaos_client, "list", side_effect=ChaosError(502, "controller unreachable: boom")):
            resp = self.client.get("/api/v1/chaos/scenarios")
        self.assertEqual(502, resp.status_code)
        self.assertIn("unreachable", resp.json()["detail"])

    def test_controller_refusals_keep_their_meaning(self):
        self.live()
        for status, expected in ((403, 403), (404, 404), (400, 400), (500, 502), (503, 502)):
            with mock.patch.object(server.chaos_client, "set", side_effect=ChaosError(status, "nope")):
                resp = self.client.post("/api/v1/chaos/scenarios/oom/start")
            self.assertEqual(expected, resp.status_code, f"controller {status}")

    def test_stop_all_stops_only_the_running_scenarios(self):
        self.live()
        third = dict(RUNNING, id="shell-injection", deployment="chaos-shell-injection")
        gone = dict(RUNNING, id="restart-storm", deployment="chaos-restart-storm", installed=False, replicas=0)
        with mock.patch.object(server.chaos_client, "list", return_value=[RUNNING, STOPPED, third, gone]), \
                mock.patch.object(server.chaos_client, "set", return_value=STOPPED) as st:
            resp = self.client.post("/api/v1/chaos/stop-all")
        self.assertEqual(200, resp.status_code)
        self.assertEqual({"stopped": ["cpu-spike", "shell-injection"]}, resp.json())
        self.assertEqual([mock.call("cpu-spike", "off"), mock.call("shell-injection", "off")], st.call_args_list)

    def test_start_and_stop_are_written_to_the_audit_trail(self):
        self.live()
        with mock.patch.object(server.chaos_client, "set", return_value=RUNNING):
            self.client.post("/api/v1/chaos/scenarios/cpu-spike/start", json={"ttl_minutes": 10})
            self.client.post("/api/v1/chaos/scenarios/cpu-spike/stop")
        with database.SessionLocal() as s:
            rows = s.query(AuditLogRecord).order_by(AuditLogRecord.id).all()
        self.assertEqual(["CHAOS_START", "CHAOS_STOP"], [r.executed_action for r in rows])
        self.assertEqual(("chaos:cpu-spike", "CHAOS_CONTROL"), (rows[0].target_pod, rows[0].problem_type))
        self.assertIn("10 minutes", rows[0].details)
        self.assertIsNone(rows[0].health_verified, "nothing was verified; it must not default to True")

    def test_a_refused_start_is_not_audited(self):
        self.live()
        with mock.patch.object(server.chaos_client, "set", side_effect=ChaosError(403, "disabled")):
            self.assertEqual(403, self.client.post("/api/v1/chaos/scenarios/oom/start").status_code)
        with database.SessionLocal() as s:
            self.assertEqual(0, s.query(AuditLogRecord).count())

    def test_action_routes_require_dashboard_token_when_set(self):
        self.live()
        with mock.patch.dict(os.environ, {"AEGIS_DASHBOARD_TOKEN": "s3cret"}), \
                mock.patch.object(server.chaos_client, "set", return_value=RUNNING) as st, \
                mock.patch.object(server.chaos_client, "list", return_value=[]):
            self.assertEqual(401, self.client.post("/api/v1/chaos/scenarios/cpu-spike/start").status_code)
            self.assertEqual(401, self.client.post("/api/v1/chaos/scenarios/cpu-spike/stop").status_code)
            self.assertEqual(401, self.client.post("/api/v1/chaos/stop-all").status_code)
            st.assert_not_called()
            ok = self.client.post("/api/v1/chaos/scenarios/cpu-spike/start", headers={"X-Aegis-Token": "s3cret"})
            self.assertEqual(200, ok.status_code)
            self.assertEqual(200, self.client.get("/api/v1/chaos/scenarios").status_code, "reading stays open")


def _resp(status, payload):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = payload
    r.text = str(payload)
    return r


class TestChaosClient(unittest.TestCase):
    URL = "http://aegis-controller.aegis-system.svc:8080/api/v1/reconcile"  # the brain-style URL, suffix is stripped

    def test_unreachable_controller_becomes_a_502_chaos_error(self):
        with mock.patch("requests.request", side_effect=requests.ConnectionError("refused")):
            with self.assertRaises(ChaosError) as cm:
                ChaosClient(self.URL, "tok").list()
        self.assertEqual(502, cm.exception.status)
        self.assertIn("unreachable", cm.exception.message)

    def test_unconfigured_url_is_a_clear_error_not_a_crash(self):
        with self.assertRaises(ChaosError) as cm:
            ChaosClient("", None).list()
        self.assertEqual(502, cm.exception.status)
        self.assertIn("GO_CONTROLLER_URL", cm.exception.message)

    def test_controller_errors_keep_their_status_and_message(self):
        with mock.patch("requests.request", return_value=_resp(403, {"status": "error", "error": "chaos controls are disabled"})):
            with self.assertRaises(ChaosError) as cm:
                ChaosClient(self.URL, "tok").set("oom", "on")
        self.assertEqual((403, "chaos controls are disabled"), (cm.exception.status, cm.exception.message))

    def test_requests_carry_the_token_the_right_url_and_only_the_given_fields(self):
        with mock.patch("requests.request", return_value=_resp(200, {"id": "oom"})) as req:
            ChaosClient(self.URL, "tok").set("oom", "on", 15)
            ChaosClient(self.URL, "tok").set("oom", "off")
        first, second = req.call_args_list
        self.assertEqual(("POST", "http://aegis-controller.aegis-system.svc:8080/api/v1/chaos"), first.args[:2])
        self.assertEqual({"Authorization": "Bearer tok"}, first.kwargs["headers"])
        self.assertEqual({"scenario": "oom", "state": "on", "ttl_minutes": 15}, first.kwargs["json"])
        self.assertEqual({"scenario": "oom", "state": "off"}, second.kwargs["json"], "no ttl unless given")

    def test_list_unwraps_the_scenarios_key(self):
        with mock.patch("requests.request", return_value=_resp(200, {"scenarios": [RUNNING]})):
            self.assertEqual([RUNNING], ChaosClient(self.URL, None).list())


class TestLiveEscalations(_Base):
    def _live_snapshot(self):
        pods = [{"pod_name": "chaos-restart-storm-7d9f-new1", "namespace": "aegis-chaos", "status": "HEALTHY"}]
        return mock.patch.object(server.live_state, "snapshot", return_value={
            "data_source": "live", "pods": pods, "sensors": {"controller": {"ok": True, "detail": "ok"}}})

    def test_live_state_lists_database_escalations_with_a_namespace(self):
        self.live()
        mark_escalated({"incident_id": "INC-LIVE-1", "target_pod": "chaos-restart-storm-7d9f-old0",
                        "problem_type": "OPERATIONAL_BUG", "recommended_action": "RESTART_POD", "confidence": 0.9},
                       "restart budget used up")
        with self._live_snapshot():
            state = self.client.get("/api/v1/telemetry/state").json()
        self.assertEqual("live", state["data_source"])
        self.assertEqual(1, len(state["escalations"]))
        esc = state["escalations"][0]
        self.assertEqual("INC-LIVE-1", esc["incident_id"])
        self.assertEqual("restart budget used up", esc["reason"])
        self.assertEqual("aegis-chaos", esc["namespace"], "found through the workload's live pods")

    def test_an_escalation_for_an_unknown_workload_has_no_namespace_rather_than_a_guess(self):
        self.live()
        mark_escalated({"incident_id": "INC-LIVE-2", "target_pod": "mystery-abc-def", "problem_type": "X",
                        "recommended_action": "RESTART_POD"}, "r")
        with self._live_snapshot():
            esc = self.client.get("/api/v1/telemetry/state").json()["escalations"][0]
        self.assertIsNone(esc["namespace"])

    def test_resolving_an_escalation_marks_it_resolved_in_the_database(self):
        mark_escalated({"incident_id": "INC-RES-1", "target_pod": "p", "problem_type": "X",
                        "recommended_action": "RESTART_POD"}, "needs a human")
        resp = self.client.post("/api/v1/escalation/resolve", json={
            "incident_id": "INC-RES-1", "target_pod": "p", "action": "CUSTOM", "notes": "looked at it"})
        self.assertEqual(200, resp.status_code)
        self.assertEqual([], list_open_escalations())

    def test_demo_mode_still_uses_the_in_memory_escalations(self):
        mark_escalated({"incident_id": "INC-DB-ONLY", "target_pod": "p", "problem_type": "X",
                        "recommended_action": "RESTART_POD"}, "db row")
        server.ESCALATED_INCIDENTS["INC-MEM"] = {"incident_id": "INC-MEM", "target_pod": "demo-pod", "reason": "demo"}
        self.addCleanup(server.ESCALATED_INCIDENTS.pop, "INC-MEM", None)
        state = self.client.get("/api/v1/telemetry/state").json()
        self.assertEqual("demo", state["data_source"])
        self.assertEqual(["INC-MEM"], [e["incident_id"] for e in state["escalations"]])


if __name__ == "__main__":
    unittest.main()
