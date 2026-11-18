import support  # noqa: F401
import unittest
from unittest import mock

from src.brain.collector import TelemetryCollector, escape_label_value
from src.brain.diagnostic_engine import DiagnosticEngine
from src.brain.metric_serializer import MetricSerializer

POD = "cartservice-6f7d8c9b5-x2k4p"
NS = "online-boutique"


def _prom(result=None):
    r = mock.Mock(status_code=200)
    r.json.return_value = {"status": "success", "data": {"result": result or []}}
    return r


def _loki(values=None):
    r = mock.Mock(status_code=200)
    r.json.return_value = {"data": {"result": [{"values": values or []}]}}
    return r


class TestQueryScoping(unittest.TestCase):
    def setUp(self):
        self.c = TelemetryCollector(prometheus_url="http://prom", loki_url="http://loki")

    def _queries(self, getter):
        return [call.kwargs["params"]["query"] for call in getter.call_args_list]

    def test_exact_selector_with_namespace(self):
        with mock.patch("requests.get", return_value=_prom()) as get:
            self.c.fetch_prometheus_metrics(POD, namespace=NS)
        for q in self._queries(get):
            self.assertIn(f'namespace="{NS}",pod="{POD}"', q)
            self.assertNotIn("pod=~", q)

    def test_injection_attempt_is_escaped(self):
        evil = 'x"} or vector(1) #'
        with mock.patch("requests.get", return_value=_prom()) as get:
            self.c.fetch_prometheus_metrics(evil, namespace=NS)
        for q in self._queries(get):
            self.assertIn('pod="x\\"} or vector(1) #"', q)
            self.assertNotIn('pod="x"}', q)

    def test_dot_in_name_is_not_a_wildcard_without_namespace(self):
        with mock.patch("requests.get", return_value=_prom()) as get:
            self.c.fetch_prometheus_metrics("a.b")
        for q in self._queries(get):
            self.assertIn("a\\\\.b", q)  # PromQL string "a\\.b" == regex a\.b

    def test_loki_queries_are_namespace_scoped_and_escaped(self):
        with mock.patch("requests.get", return_value=_loki()) as get:
            self.c.fetch_loki_logs(POD, namespace=NS)
        queries = self._queries(get)
        self.assertTrue(queries)
        self.assertTrue(all(f'namespace="{NS}"' in q for q in queries), queries)
        with mock.patch("requests.get", return_value=_loki()) as get:
            self.c.fetch_loki_logs('x"} |= "', namespace=NS)
        self.assertTrue(all('x\\"}' in q for q in self._queries(get)))

    def test_escape_label_value(self):
        self.assertEqual(escape_label_value('a"b\\c\nd'), 'a\\"b\\\\c d')


class TestNoDataIsNotNormal(unittest.TestCase):
    def test_empty_prometheus_series_report_none_not_zero(self):
        c = TelemetryCollector(prometheus_url="http://prom", loki_url="http://loki")
        with mock.patch("requests.get", return_value=_prom()):
            m = c.fetch_prometheus_metrics(POD, namespace=NS)
        self.assertTrue(m["sensor_ok"])
        for key in ("cpu_usage_pct", "memory_mb", "memory_pct", "memory_limit_mb", "total_requests", "error_500_count"):
            self.assertIsNone(m[key], key)

    def test_serializer_says_no_data_instead_of_normal(self):
        text = MetricSerializer.serialize_prometheus_metrics("p", {
            "sensor_ok": True, "cpu_usage_pct": None, "memory_mb": None, "memory_pct": None,
            "memory_limit_mb": None, "total_requests": None, "error_500_count": None, "avg_latency_ms": None})
        self.assertIn("no data", text)
        self.assertNotIn("0.0% (Status: NORMAL)", text)
        self.assertNotIn("Status: NORMAL", text)

    def test_serializer_still_reports_real_numbers(self):
        text = MetricSerializer.serialize_prometheus_metrics("p", {
            "sensor_ok": True, "cpu_usage_pct": 91.0, "memory_mb": 400.0, "memory_pct": 90.0,
            "total_requests": 100, "error_500_count": 20, "avg_latency_ms": 5.0})
        self.assertIn("CPU Usage: 91.0% (Status: ELEVATED)", text)
        self.assertIn("NEAR OOM", text)
        self.assertIn("(20.0%, Status: HIGH)", text)

    def test_cpu_above_alert_threshold_reads_elevated(self):
        # AegisHighPodCPU fires at > 70%. A live incident at 77.7% read "NORMAL" and the model called the
        # firing alert a false positive, so the serializer must agree with the alert rule.
        text = MetricSerializer.serialize_prometheus_metrics("p", {
            "sensor_ok": True, "cpu_usage_pct": 77.7, "memory_mb": 10.0, "memory_pct": 10.0,
            "total_requests": None, "error_500_count": None, "avg_latency_ms": None})
        self.assertIn("CPU Usage: 77.7% (Status: ELEVATED)", text)
        below = MetricSerializer.serialize_prometheus_metrics("p", {
            "sensor_ok": True, "cpu_usage_pct": 69.0, "memory_mb": 10.0, "memory_pct": 10.0,
            "total_requests": None, "error_500_count": None, "avg_latency_ms": None})
        self.assertIn("CPU Usage: 69.0% (Status: NORMAL)", below)


class TestEnginePassesNamespace(unittest.TestCase):
    def test_engine_passes_namespace_to_every_collector_call(self):
        engine = DiagnosticEngine()
        metrics = {"sensor_ok": True, "cpu_usage_pct": 50.0, "memory_mb": 1.0, "memory_pct": 1.0,
                   "total_requests": 0, "error_500_count": 0, "avg_latency_ms": 0.0, "source": "t"}
        with mock.patch.object(engine.collector, "check_sensors", return_value={}), mock.patch.object(
            engine.collector, "any_critical_dark", return_value=False
        ), mock.patch.object(engine.collector, "fetch_prometheus_metrics", return_value=metrics) as prom, mock.patch.object(
            engine.collector, "fetch_loki_logs", return_value=[]
        ) as loki, mock.patch.object(engine.collector, "fetch_falco_alerts", return_value=[]) as falco:
            engine.diagnose_incident(pod_name=POD, alert_type="AegisHighPodCPU", namespace=NS)
        self.assertEqual(prom.call_args.kwargs.get("namespace"), NS)
        self.assertEqual(loki.call_args.kwargs.get("namespace"), NS)
        self.assertEqual(falco.call_args.kwargs.get("namespace"), NS)


if __name__ == "__main__":
    unittest.main()
