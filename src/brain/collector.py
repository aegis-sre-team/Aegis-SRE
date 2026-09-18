import logging
import os
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("aegis-brain-collector")


class SensorDarkError(Exception):
    """Raised when a required telemetry sensor is unreachable or returns unusable data."""

    def __init__(self, sensor: str, detail: str):
        self.sensor = sensor
        self.detail = detail
        super().__init__(f"{sensor} dark: {detail}")


class TelemetryCollector:
    """
    Honest telemetry collector for Phase 3.
    Fail closed: never invent healthy metrics / fake Falco events when sensors are dark.
    """

    def __init__(
        self,
        prometheus_url: str = None,
        loki_url: str = None,
        request_timeout: float = None,
    ):
        self.prometheus_url = (prometheus_url or os.getenv("PROMETHEUS_URL", "http://localhost:9090")).rstrip("/")
        self.loki_url = (loki_url or os.getenv("LOKI_URL", "http://localhost:3100")).rstrip("/")
        timeout = request_timeout or float(os.getenv("AEGIS_SENSOR_TIMEOUT", "3.0"))
        self.timeout = (min(1.0, timeout), timeout)
        self._sensor_health: Dict[str, Dict[str, Any]] = {
            "prometheus": {"ok": False, "detail": "not_checked"},
            "loki": {"ok": False, "detail": "not_checked"},
            "falco_via_loki": {"ok": False, "detail": "not_checked"},
        }

    @property
    def sensor_health(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._sensor_health)

    def _mark(self, sensor: str, ok: bool, detail: str) -> None:
        self._sensor_health[sensor] = {"ok": ok, "detail": detail}

    def check_sensors(self) -> Dict[str, Dict[str, Any]]:
        """Probe Prometheus + Loki readiness. Updates sensor_health."""
        try:
            resp = requests.get(f"{self.prometheus_url}/-/ready", timeout=self.timeout)
            if resp.status_code == 200:
                self._mark("prometheus", True, "ready")
            else:
                self._mark("prometheus", False, f"HTTP {resp.status_code}")
        except Exception as e:
            self._mark("prometheus", False, str(e))

        try:
            resp = requests.get(f"{self.loki_url}/ready", timeout=self.timeout)
            if resp.status_code == 200:
                self._mark("loki", True, "ready")
            else:
                # Loki sometimes returns 503 briefly while ready endpoint exists
                resp2 = requests.get(f"{self.loki_url}/loki/api/v1/labels", timeout=self.timeout)
                if resp2.status_code == 200:
                    self._mark("loki", True, "labels_ok")
                else:
                    self._mark("loki", False, f"HTTP {resp.status_code}")
        except Exception as e:
            self._mark("loki", False, str(e))

        # Falco path: Loki stream {app="falco"} must be queryable (may be empty)
        if self._sensor_health["loki"]["ok"]:
            try:
                resp = requests.get(
                    f"{self.loki_url}/loki/api/v1/query_range",
                    params={"query": '{app="falco"}', "limit": 1},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    self._mark("falco_via_loki", True, "queryable")
                else:
                    self._mark("falco_via_loki", False, f"HTTP {resp.status_code}")
            except Exception as e:
                self._mark("falco_via_loki", False, str(e))
        else:
            self._mark("falco_via_loki", False, "loki_dark")

        return self.sensor_health

    def any_critical_dark(self) -> bool:
        """Prometheus or Loki down => cannot diagnose honestly."""
        h = self.sensor_health
        return not (h.get("prometheus", {}).get("ok") and h.get("loki", {}).get("ok"))

    def _prom_query(self, query: str) -> Optional[List[dict]]:
        resp = requests.get(
            f"{self.prometheus_url}/api/v1/query",
            params={"query": query},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise SensorDarkError("prometheus", f"query HTTP {resp.status_code}: {query[:80]}")
        payload = resp.json()
        if payload.get("status") != "success":
            raise SensorDarkError("prometheus", f"query status={payload.get('status')}")
        return payload.get("data", {}).get("result", [])

    def fetch_prometheus_metrics(self, pod_name: str) -> dict:
        """
        Query live cAdvisor-backed metrics for the target pod.
        Returns zeros only when the sensor answered and series are empty — never fake healthy baselines.
        Raises SensorDarkError when Prometheus is unreachable.
        """
        metrics_data = {
            "total_requests": 0,
            "error_500_count": 0,
            "avg_latency_ms": 0.0,
            "memory_mb": 0.0,
            "memory_limit_mb": 0.0,
            "memory_pct": 0.0,
            "cpu_usage_pct": 0.0,
            "sensor_ok": False,
            "source": "prometheus+cadvisor",
        }

        try:
            # Prefer cAdvisor CPU ratio vs limit (Boutique /metrics often broken gRPC)
            cpu_q = (
                f'(sum(rate(container_cpu_usage_seconds_total{{pod=~".*{pod_name}.*",container!="",container!="POD"}}[1m])) '
                f'/ sum(container_spec_cpu_quota{{pod=~".*{pod_name}.*",container!="",container!="POD"}} '
                f'/ container_spec_cpu_period{{pod=~".*{pod_name}.*",container!="",container!="POD"}})) * 100'
            )
            cpu_res = self._prom_query(cpu_q)
            if cpu_res:
                metrics_data["cpu_usage_pct"] = round(float(cpu_res[0]["value"][1]), 1)

            mem_q = f'sum(container_memory_working_set_bytes{{pod=~".*{pod_name}.*",container!="",container!="POD"}})/1024/1024'
            mem_res = self._prom_query(mem_q)
            if mem_res:
                metrics_data["memory_mb"] = round(float(mem_res[0]["value"][1]), 1)

            lim_q = f'sum(container_spec_memory_limit_bytes{{pod=~".*{pod_name}.*",container!="",container!="POD"}})/1024/1024'
            lim_res = self._prom_query(lim_q)
            if lim_res:
                lim = float(lim_res[0]["value"][1])
                # Ignore absurdly large "unlimited" specs
                if 0 < lim < 1_000_000:
                    metrics_data["memory_limit_mb"] = round(lim, 1)
                    if lim > 0:
                        metrics_data["memory_pct"] = round(
                            (metrics_data["memory_mb"] / lim) * 100.0, 1
                        )

            # Optional HTTP counters if present (Boutique rarely exposes them)
            try:
                req_res = self._prom_query(f'sum(http_requests_total{{pod=~".*{pod_name}.*"}})')
                if req_res:
                    metrics_data["total_requests"] = int(float(req_res[0]["value"][1]))
                err_res = self._prom_query(
                    f'sum(http_requests_total{{pod=~".*{pod_name}.*",status=~"5.."}})'
                )
                if err_res:
                    metrics_data["error_500_count"] = int(float(err_res[0]["value"][1]))
            except SensorDarkError:
                pass

            metrics_data["sensor_ok"] = True
            self._mark("prometheus", True, "query_ok")
        except SensorDarkError as e:
            self._mark("prometheus", False, e.detail)
            raise
        except Exception as e:
            self._mark("prometheus", False, str(e))
            raise SensorDarkError("prometheus", str(e)) from e

        return metrics_data

    def fetch_loki_logs(self, pod_name: str, limit: int = 15) -> List[str]:
        """
        Query Loki for recent pod logs. Empty list is honest (no lines).
        Raises SensorDarkError when Loki is unreachable.
        Avoids overly broad app=~ prefixes (e.g. 'chaos' matching all chaos pods).
        """
        logs: List[str] = []
        query_url = f"{self.loki_url}/loki/api/v1/query_range"

        # Prefer exact-ish pod match; optional app label only if pod name looks like a
        # deployment prefix with hash (app = first label segment only when long enough
        # and not a shared namespace prefix like "chaos").
        queries = [f'{{pod=~".*{pod_name}.*"}}']
        parts = pod_name.split("-") if pod_name else []
        if len(parts) >= 2:
            # Online Boutique style: frontend-xxxxx -> app=frontend
            # Skip shared prefixes used by many workloads in aegis-chaos.
            app_label = parts[0]
            if app_label not in {"chaos", "aegis"} and len(app_label) >= 4:
                queries.append(f'{{app="{app_label}"}}')

        try:
            for query in queries:
                resp = requests.get(
                    query_url,
                    params={"query": query, "limit": limit},
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    raise SensorDarkError("loki", f"HTTP {resp.status_code} for {query}")
                streams = resp.json().get("data", {}).get("result", [])
                for stream in streams:
                    for entry in stream.get("values", []):
                        logs.append(entry[1])
                if logs:
                    break

            self._mark("loki", True, "query_ok")
        except SensorDarkError:
            raise
        except Exception as e:
            self._mark("loki", False, str(e))
            raise SensorDarkError("loki", str(e)) from e

        return logs

    def fetch_falco_alerts(
        self,
        pod_name: str,
        limit: int = 25,
        security_context: bool = False,
    ) -> List[str]:
        """
        Query Loki stream {{app="falco"}} for security events.
        Does NOT fabricate T1059 bait when empty.

        Matching rules (K3s Falco often lacks k8s.pod.name):
        - Always include lines that mention pod_name.
        - If security_context=True (shell/Falco alert path), also include
          SECURITY_ALERT / T1059 / T1552 / shell-spawn lines.
        - If security_context=False (BUG path), do NOT attach unrelated
          cluster-wide shell noise to OOM/CPU incidents.
        """
        falco_alerts: List[str] = []
        query_url = f"{self.loki_url}/loki/api/v1/query_range"

        try:
            resp = requests.get(
                query_url,
                params={"query": '{app="falco"}', "limit": limit},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                raise SensorDarkError("falco_via_loki", f"HTTP {resp.status_code}")

            streams = resp.json().get("data", {}).get("result", [])
            pod_token = (pod_name or "").lower()
            security_markers = (
                "security_alert",
                "t1059",
                "t1552",
                "shell spawned",
                "sensitive file read",
            )
            for stream in streams:
                for entry in stream.get("values", []):
                    log_msg = entry[1]
                    lower = log_msg.lower()
                    pod_hit = bool(pod_token) and pod_token in lower
                    security_hit = any(m in lower for m in security_markers)
                    if pod_hit:
                        falco_alerts.append(log_msg)
                    elif security_context and security_hit:
                        falco_alerts.append(log_msg)

            self._mark("falco_via_loki", True, f"events={len(falco_alerts)}")
        except SensorDarkError:
            raise
        except Exception as e:
            self._mark("falco_via_loki", False, str(e))
            raise SensorDarkError("falco_via_loki", str(e)) from e

        return falco_alerts
