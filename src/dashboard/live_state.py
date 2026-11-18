"""Live cluster state for the dashboard (Phase 7).

Pods come from the Go controller (the Kubernetes API), CPU/memory from Prometheus (cAdvisor).
Nothing is invented: a source that cannot be reached is reported as down and its numbers are
``None``, never a plausible-looking default.
"""
import copy
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.brain.collector import escape_label_value

logger = logging.getLogger("aegis-live-state")

_RECONCILE_SUFFIX = "/api/v1/reconcile"


def _controller_base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url.endswith(_RECONCILE_SUFFIX):
        url = url[: -len(_RECONCILE_SUFFIX)]
    return url


def map_pod_status(summary: Dict[str, Any]) -> str:
    """Translate a controller pod summary into the status vocabulary the UI already uses."""
    phase = summary.get("phase")
    if summary.get("quarantined"):
        return "QUARANTINED"
    if phase == "Failed":
        return "FAILED"
    if phase == "Succeeded":
        return "COMPLETED"
    if phase == "Running" and summary.get("ready"):
        return "HEALTHY"
    return "DEGRADED"


class LiveClusterState:
    def __init__(self, controller_url: str, prometheus_url: str, namespaces: List[str],
                 token: Optional[str] = None, timeout: float = 3.0, cache_ttl: float = 10.0,
                 snapshot_ttl: float = 0.0):
        self.base = _controller_base(controller_url)
        self.prometheus_url = (prometheus_url or "").rstrip("/")
        self.namespaces = list(namespaces)
        self.token = token
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        # Seconds a whole snapshot may be reused. 0 = never (the default, and what the tests rely on).
        # Several callers ask at once (the tick loop, REST polls, a new WebSocket), and through a tunnel
        # one snapshot costs seconds, so the server sets a few seconds here.
        self.snapshot_ttl = snapshot_ttl
        self._avail: Optional[Tuple[float, bool]] = None
        self._snap: Optional[Tuple[float, Dict[str, Any]]] = None
        self._snap_lock = threading.Lock()

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def controller_available(self) -> bool:
        """True when the controller answers /healthz. Cached briefly so polling stays cheap."""
        if not self.base:
            return False
        now = time.monotonic()
        if self._avail and now - self._avail[0] < self.cache_ttl:
            return self._avail[1]
        try:
            ok = requests.get(f"{self.base}/healthz", timeout=self.timeout).status_code == 200
        except Exception:
            ok = False
        self._avail = (now, ok)
        return ok

    def _controller_pods(self, namespace: str) -> List[Dict[str, Any]]:
        resp = requests.get(f"{self.base}/api/v1/pods", params={"namespace": namespace},
                            headers=self._headers(), timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"controller HTTP {resp.status_code} for namespace {namespace}")
        return resp.json().get("pods", [])

    def _prom_by_pod(self, query: str) -> Dict[Tuple[str, str], float]:
        resp = requests.get(f"{self.prometheus_url}/api/v1/query", params={"query": query}, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"prometheus HTTP {resp.status_code}")
        out: Dict[Tuple[str, str], float] = {}
        for item in resp.json().get("data", {}).get("result", []):
            metric = item.get("metric", {})
            key = (metric.get("namespace"), metric.get("pod"))  # a pod name alone is ambiguous across namespaces
            try:
                out[key] = round(float(item["value"][1]), 1)
            except (KeyError, TypeError, ValueError):
                continue
        return out

    def _selector(self) -> str:
        ns = "|".join(escape_label_value(re.escape(n)) for n in self.namespaces)
        return f'namespace=~"{ns}",container!="",container!="POD"'

    def snapshot(self) -> Dict[str, Any]:
        """The live picture. Reused for ``snapshot_ttl`` seconds when that is set; callers get copies."""
        if self.snapshot_ttl <= 0:
            return self._build_snapshot()
        with self._snap_lock:  # concurrent callers wait here and then share one fetch
            if self._snap and time.monotonic() - self._snap[0] < self.snapshot_ttl:
                return copy.deepcopy(self._snap[1])
            snap = self._build_snapshot()
            self._snap = (time.monotonic(), snap)
            return copy.deepcopy(snap)

    def _build_snapshot(self) -> Dict[str, Any]:
        sensors: Dict[str, Dict[str, Any]] = {}
        pods: List[Dict[str, Any]] = []
        error: Optional[str] = None
        stamp = time.strftime("%H:%M:%S")

        sel = self._selector()
        cpu_query = (
            f"100 * sum by (namespace, pod) (rate(container_cpu_usage_seconds_total{{{sel}}}[2m])) / "
            f"sum by (namespace, pod) (container_spec_cpu_quota{{{sel}}} / container_spec_cpu_period{{{sel}}} > 0)"
        )
        mem_query = (
            f"100 * sum by (namespace, pod) (container_memory_working_set_bytes{{{sel}}}) / "
            f"sum by (namespace, pod) (container_spec_memory_limit_bytes{{{sel}}} > 0)"
        )

        # Every upstream call is independent, and through a tunnel each one costs ~1.5 s, so run them together.
        with ThreadPoolExecutor(max_workers=len(self.namespaces) + 2) as pool:
            pod_calls = [(ns, pool.submit(self._controller_pods, ns)) for ns in self.namespaces]
            cpu_call = pool.submit(self._prom_by_pod, cpu_query)
            mem_call = pool.submit(self._prom_by_pod, mem_query)

            raw: List[Tuple[str, Dict[str, Any]]] = []
            try:
                for ns, call in pod_calls:
                    raw.extend((ns, p) for p in call.result())
                sensors["controller"] = {"ok": True, "detail": "ok"}
            except Exception as e:
                sensors["controller"] = {"ok": False, "detail": str(e)}
                error = f"controller unreachable: {e}"
                raw = []

            # A metric that arrived is kept even when the other one failed; Prometheus is down if either did.
            cpu: Dict[Tuple[str, str], float] = {}
            mem: Dict[Tuple[str, str], float] = {}
            prom_error: Optional[str] = None
            for name, call in (("cpu", cpu_call), ("mem", mem_call)):
                try:
                    (cpu if name == "cpu" else mem).update(call.result())
                except Exception as e:
                    prom_error = prom_error or str(e)
            sensors["prometheus"] = {"ok": prom_error is None, "detail": prom_error or "ok"}

        for ns, p in raw:
            name = p.get("name", "")
            pods.append({
                "pod_name": name,
                "namespace": ns,
                "app": p.get("app"),
                "node": p.get("node"),
                "ip": p.get("ip"),
                "status": map_pod_status(p),
                "restart_count": p.get("restarts", 0),
                "cpu_pct": cpu.get((ns, name)),
                "mem_pct": mem.get((ns, name)),
                "error_rate_pct": None,  # no per-pod error-rate source on this cluster
                "last_updated": stamp,
            })

        snap: Dict[str, Any] = {"data_source": "live", "pods": pods, "sensors": sensors}
        if error:
            snap["error"] = error
        return snap


def resolve_data_source(mode: str, state: Any) -> str:
    """auto = live only when the controller answers; live/demo are explicit and never silently swapped."""
    mode = (mode or "auto").lower()
    if mode not in ("auto", "live", "demo"):
        mode = "auto"
    if mode == "live":
        return "live"
    if mode == "demo":
        return "demo"
    return "live" if state.controller_available() else "demo"


def sensor_startup_logs(sensors: Dict[str, Dict[str, Any]], data_source: str) -> List[Tuple[str, str, str]]:
    """Terminal log lines describing the REAL sensor state at startup."""
    if data_source == "demo":
        return [("WARN", "SYSTEM", "DEMO MODE: no live cluster controller detected; pod telemetry is simulated.")]
    logs: List[Tuple[str, str, str]] = [("SUCCESS", "SYSTEM", "Aegis-SRE dashboard online (live data).")]
    for name, st in sorted(sensors.items()):
        if st.get("ok"):
            logs.append(("INFO", "TELEMETRY", f"{name}: reachable"))
        else:
            logs.append(("WARN", "TELEMETRY", f"{name} NOT connected: {st.get('detail', 'unknown error')}"))
    return logs
