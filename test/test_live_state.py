import support  # noqa: F401
import os
import unittest
from unittest import mock

import requests
from fastapi.testclient import TestClient

from src.dashboard import server
from src.dashboard.live_state import (
    LiveClusterState,
    map_pod_status,
    resolve_data_source,
    sensor_startup_logs,
)

CTRL = "http://aegis-controller.aegis-system.svc:8080/api/v1/reconcile"
PROM = "http://prometheus.monitoring.svc:9090"
POD = "cartservice-6f7d8c9b5-x2k4p"


def _resp(body, status=200):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = body
    return r


def _pod(name=POD, phase="Running", ready=True, restarts=0, quarantined=False, app="cartservice"):
    return {"name": name, "phase": phase, "ready": ready, "restarts": restarts, "node": "node-1",
            "ip": "10.42.0.9", "app": app, "quarantined": quarantined}


def _prom_vector(values):
    """values: {pod: v} (namespace defaults to online-boutique) or {(namespace, pod): v}."""
    out = []
    for key, v in values.items():
        ns, pod = key if isinstance(key, tuple) else ("online-boutique", key)
        out.append({"metric": {"namespace": ns, "pod": pod}, "value": [0, str(v)]})
    return {"status": "success", "data": {"result": out}}


def fake_get(pods_by_ns, cpu=None, mem=None, prom_down=False, controller_down=False):
    def _get(url, params=None, headers=None, timeout=None):
        if url.endswith("/healthz"):
            if controller_down:
                raise requests.ConnectionError("refused")
            return _resp({"status": "healthy", "dry_run": True, "cluster_connected": True})
        if "/api/v1/pods" in url:
            if controller_down:
                raise requests.ConnectionError("refused")
            ns = (params or {}).get("namespace")
            return _resp({"namespace": ns, "pods": pods_by_ns.get(ns, [])})
        if "/api/v1/query" in url:
            if prom_down:
                raise requests.ConnectionError("prometheus down")
            q = params["query"]
            if "cpu_usage" in q:
                return _resp(_prom_vector(cpu or {}))
            if "working_set" in q:
                return _resp(_prom_vector(mem or {}))
            return _resp(_prom_vector({}))
        raise AssertionError(f"unexpected URL {url}")
    return _get


class TestLiveSnapshot(unittest.TestCase):
    def _state(self):
        return LiveClusterState(controller_url=CTRL, prometheus_url=PROM,
                                namespaces=["online-boutique", "aegis-chaos"], token="tok")

    def test_snapshot_maps_controller_pods_and_prometheus(self):
        get = fake_get({"online-boutique": [_pod(restarts=2)], "aegis-chaos": [_pod("chaos-oom-1", app="chaos-oom")]},
                       cpu={POD: 41.234}, mem={POD: 62.5})
        with mock.patch("requests.get", side_effect=get):
            snap = self._state().snapshot()
        self.assertEqual(snap["data_source"], "live")
        by_name = {p["pod_name"]: p for p in snap["pods"]}
        cart = by_name[POD]
        self.assertEqual((cart["status"], cart["restart_count"], cart["namespace"]), ("HEALTHY", 2, "online-boutique"))
        self.assertEqual((cart["cpu_pct"], cart["mem_pct"]), (41.2, 62.5))
        self.assertEqual(by_name["chaos-oom-1"]["namespace"], "aegis-chaos")
        self.assertTrue(snap["sensors"]["controller"]["ok"])
        self.assertTrue(snap["sensors"]["prometheus"]["ok"])

    def test_same_pod_name_in_two_namespaces_is_not_merged(self):
        get = fake_get({"online-boutique": [_pod("web-1", app="web")], "aegis-chaos": [_pod("web-1", app="web")]},
                       cpu={("online-boutique", "web-1"): 10.0, ("aegis-chaos", "web-1"): 90.0},
                       mem={("online-boutique", "web-1"): 20.0, ("aegis-chaos", "web-1"): 80.0})
        with mock.patch("requests.get", side_effect=get):
            snap = self._state().snapshot()
        by_ns = {p["namespace"]: p for p in snap["pods"]}
        self.assertEqual((by_ns["online-boutique"]["cpu_pct"], by_ns["online-boutique"]["mem_pct"]), (10.0, 20.0))
        self.assertEqual((by_ns["aegis-chaos"]["cpu_pct"], by_ns["aegis-chaos"]["mem_pct"]), (90.0, 80.0))

    def test_prometheus_queries_group_by_namespace_and_escape_the_selector(self):
        queries = []

        def spy(url, params=None, headers=None, timeout=None):
            if "/api/v1/query" in url:
                queries.append(params["query"])
            return fake_get({"online-boutique": []})(url, params, headers, timeout)

        state = LiveClusterState(controller_url=CTRL, prometheus_url=PROM, namespaces=["online-boutique", 'we"ird.ns'])
        with mock.patch("requests.get", side_effect=spy):
            state.snapshot()
        self.assertTrue(queries)
        for q in queries:
            self.assertIn("by (namespace, pod)", q)
            self.assertIn(r'namespace=~"online\\-boutique|we\"ird\\.ns"', q)

    def test_prometheus_down_reports_unknown_not_fake_numbers(self):
        get = fake_get({"online-boutique": [_pod()]}, prom_down=True)
        with mock.patch("requests.get", side_effect=get):
            snap = self._state().snapshot()
        pod = snap["pods"][0]
        self.assertIsNone(pod["cpu_pct"])
        self.assertIsNone(pod["mem_pct"])
        self.assertIsNone(pod["error_rate_pct"])
        self.assertFalse(snap["sensors"]["prometheus"]["ok"])
        self.assertTrue(snap["sensors"]["controller"]["ok"])

    def test_controller_down_yields_no_pods_and_an_error(self):
        with mock.patch("requests.get", side_effect=fake_get({}, controller_down=True)):
            snap = self._state().snapshot()
        self.assertEqual(snap["pods"], [])
        self.assertFalse(snap["sensors"]["controller"]["ok"])
        self.assertTrue(snap["error"])

    def test_requests_carry_the_bearer_token(self):
        seen = []

        def spy(url, params=None, headers=None, timeout=None):
            seen.append((url, headers))
            return fake_get({"online-boutique": []})(url, params, headers, timeout)

        with mock.patch("requests.get", side_effect=spy):
            self._state().snapshot()
        ctrl_calls = [h for u, h in seen if "aegis-controller" in u]
        self.assertTrue(ctrl_calls)
        self.assertTrue(all(h and h.get("Authorization") == "Bearer tok" for h in ctrl_calls))

    def test_status_mapping(self):
        cases = [
            (_pod(), "HEALTHY"),
            (_pod(quarantined=True), "QUARANTINED"),
            (_pod(ready=False), "DEGRADED"),
            (_pod(phase="Pending", ready=False), "DEGRADED"),
            (_pod(phase="Failed", ready=False), "FAILED"),
            (_pod(phase="Succeeded", ready=False), "COMPLETED"),
        ]
        for summary, want in cases:
            self.assertEqual(map_pod_status(summary), want, summary)


class TestDataSourceResolution(unittest.TestCase):
    def test_auto_uses_live_only_when_controller_answers(self):
        up = mock.Mock(controller_available=mock.Mock(return_value=True))
        down = mock.Mock(controller_available=mock.Mock(return_value=False))
        self.assertEqual(resolve_data_source("auto", up), "live")
        self.assertEqual(resolve_data_source("auto", down), "demo")

    def test_explicit_modes_are_respected(self):
        down = mock.Mock(controller_available=mock.Mock(return_value=False))
        self.assertEqual(resolve_data_source("live", down), "live")  # never silently shows fake data
        self.assertEqual(resolve_data_source("demo", down), "demo")

    def test_unknown_mode_falls_back_to_auto(self):
        up = mock.Mock(controller_available=mock.Mock(return_value=True))
        self.assertEqual(resolve_data_source("banana", up), "live")

    def test_no_controller_url_means_unavailable_without_network(self):
        with mock.patch("requests.get") as get:
            self.assertFalse(LiveClusterState("", PROM, ["x"]).controller_available())
        get.assert_not_called()


class TestStartupLogsAreHonest(unittest.TestCase):
    def test_dark_sensors_are_reported_as_dark(self):
        sensors = {"prometheus": {"ok": False, "detail": "timeout"}, "loki": {"ok": True, "detail": "ok"},
                   "falco_via_loki": {"ok": False, "detail": "no falco stream"}}
        logs = sensor_startup_logs(sensors, "live")
        text = " | ".join(m for _, _, m in logs)
        self.assertIn("prometheus", text.lower())
        self.assertIn("timeout", text)
        self.assertTrue(any(level in ("WARN", "ERROR", "ALERT") for level, _, _ in logs))
        self.assertNotIn("connected", text.lower().replace("not connected", ""))

    def test_all_ok_is_reported_as_ok(self):
        ok = {"prometheus": {"ok": True, "detail": "ok"}, "loki": {"ok": True, "detail": "ok"},
              "falco_via_loki": {"ok": True, "detail": "ok"}}
        logs = sensor_startup_logs(ok, "live")
        self.assertTrue(all(level in ("INFO", "SUCCESS") for level, _, _ in logs))

    def test_demo_mode_says_so(self):
        logs = sensor_startup_logs({}, "demo")
        self.assertIn("demo", " ".join(m for _, _, m in logs).lower())


class TestDashboardServerLiveBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(server.app)

    def setUp(self):
        support.reset_restart_state()
        p = mock.patch.dict(os.environ, {"DASHBOARD_MODE": "demo"})
        p.start()
        self.addCleanup(p.stop)

    def test_payload_includes_data_source(self):
        data = self.client.get("/api/v1/telemetry/state").json()
        self.assertEqual(data["data_source"], "demo")

    def test_live_payload_uses_live_snapshot(self):
        snap = {"data_source": "live", "pods": [{"pod_name": POD, "namespace": "online-boutique", "status": "HEALTHY",
                                                 "cpu_pct": None, "mem_pct": None, "error_rate_pct": None,
                                                 "restart_count": 0, "last_updated": "10:00:00"}],
                "sensors": {"controller": {"ok": True, "detail": "ok"}, "prometheus": {"ok": False, "detail": "down"}}}
        with mock.patch.dict(os.environ, {"DASHBOARD_MODE": "live"}), mock.patch.object(
            server.live_state, "snapshot", return_value=snap
        ):
            data = self.client.get("/api/v1/telemetry/state").json()
        self.assertEqual(data["data_source"], "live")
        self.assertEqual([p["pod_name"] for p in data["pods"]], [POD])
        self.assertFalse(data["sensors"]["prometheus"]["ok"])

    def test_forensics_404_in_live_mode_when_nothing_was_captured(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_MODE": "live"}):
            resp = self.client.get("/api/v1/forensics/never-captured-pod")
        self.assertEqual(resp.status_code, 404)

    def test_forensics_demo_sample_is_labelled(self):
        data = self.client.get("/api/v1/forensics/never-captured-pod").json()
        self.assertTrue(data["demo"])

    def test_forensics_returns_the_real_file_when_present(self):
        import json
        path = "logs/forensics_unit-test-real-pod.json"
        os.makedirs("logs", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"target_pod": "unit-test-real-pod", "data_source": "cluster", "process_tree": []}, f)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        with mock.patch.dict(os.environ, {"DASHBOARD_MODE": "live"}):
            resp = self.client.get("/api/v1/forensics/unit-test-real-pod")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data_source"], "cluster")

    def test_hitl_restart_calls_the_executor(self):
        from src.controller.executor import ActionExecutionResult

        ok = ActionExecutionResult(True, "RESTART_POD", POD, "done", "COMPLETED_GO_K8S_CLUSTER")
        with mock.patch.object(server.action_executor, "execute_decision", return_value=ok) as ex:
            resp = self.client.post("/api/v1/escalation/resolve", json={
                "incident_id": "INC-1", "target_pod": POD, "action": "RESTART_POD", "namespace": "online-boutique"})
        self.assertEqual(resp.status_code, 200)
        decision = ex.call_args.args[0]
        self.assertEqual((decision.final_action, decision.namespace, decision.target_pod),
                         ("RESTART_POD", "online-boutique", POD))
        self.assertTrue(decision.approved)

    def test_hitl_failure_is_reported_not_swallowed(self):
        from src.controller.executor import ActionExecutionResult

        bad = ActionExecutionResult(False, "RESTART_POD", POD, "Go controller unreachable", "FAILED_CONTROLLER_UNREACHABLE")
        with mock.patch.object(server.action_executor, "execute_decision", return_value=bad):
            resp = self.client.post("/api/v1/escalation/resolve", json={
                "incident_id": "INC-2", "target_pod": POD, "action": "RESTART_POD"})
        self.assertEqual(resp.status_code, 502)
        self.assertIn("FAILED_CONTROLLER_UNREACHABLE", resp.json()["detail"])

    def test_hitl_live_requires_a_namespace(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_MODE": "live"}), mock.patch.object(
            server.action_executor, "execute_decision"
        ) as ex:
            resp = self.client.post("/api/v1/escalation/resolve", json={
                "incident_id": "INC-4", "target_pod": POD, "action": "RESTART_POD"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("namespace", resp.json()["detail"].lower())
        ex.assert_not_called()

    def test_hitl_protected_namespace_is_forbidden_in_any_mode(self):
        with mock.patch.object(server.action_executor, "execute_decision") as ex:
            resp = self.client.post("/api/v1/escalation/resolve", json={
                "incident_id": "INC-5", "target_pod": "coredns-1", "action": "RESTART_POD", "namespace": "kube-system"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("kube-system", resp.json()["detail"])
        ex.assert_not_called()

    def test_hitl_allowlist_is_enforced(self):
        with mock.patch.dict(os.environ, {"AEGIS_ALLOWED_NAMESPACES": "online-boutique"}), mock.patch.object(
            server.action_executor, "execute_decision"
        ) as ex:
            resp = self.client.post("/api/v1/escalation/resolve", json={
                "incident_id": "INC-6", "target_pod": POD, "action": "RESTART_POD", "namespace": "aegis-chaos"})
        self.assertEqual(resp.status_code, 403)
        ex.assert_not_called()

    def test_hitl_demo_without_namespace_still_works(self):
        from src.controller.executor import ActionExecutionResult

        ok = ActionExecutionResult(True, "RESTART_POD", POD, "done", "COMPLETED_DRY_RUN")
        with mock.patch.object(server.action_executor, "execute_decision", return_value=ok):
            resp = self.client.post("/api/v1/escalation/resolve", json={
                "incident_id": "INC-7", "target_pod": POD, "action": "RESTART_POD"})
        self.assertEqual(resp.status_code, 200)

    def test_hitl_unknown_action_is_rejected(self):
        resp = self.client.post("/api/v1/escalation/resolve", json={
            "incident_id": "INC-3", "target_pod": POD, "action": "DELETE_NAMESPACE"})
        self.assertEqual(resp.status_code, 400)

    def test_pipeline_events_stream_new_audit_rows_once(self):
        from src.db.database import SessionLocal, init_db
        from src.db.models import AuditLogRecord

        init_db()
        _, last_id = server.collect_pipeline_events(None)
        with SessionLocal() as s:
            s.add(AuditLogRecord(timestamp="2026-11-17T10:00:00Z", target_pod=POD, problem_type="OPERATIONAL_BUG",
                                 executed_action="RESTART_POD", execution_success=True,
                                 status_code="COMPLETED_GO_K8S_CLUSTER", details="rollout restart", health_verified=True))
            s.commit()
        events, new_last = server.collect_pipeline_events(last_id)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual((ev["event"], ev["kind"], ev["target_pod"], ev["executed_action"]),
                         ("PIPELINE_EVENT", "audit", POD, "RESTART_POD"))
        again, _ = server.collect_pipeline_events(new_last)
        self.assertEqual(again, [])


if __name__ == "__main__":
    unittest.main()
