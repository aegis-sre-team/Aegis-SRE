"""Dashboard -> Go controller client for the chaos start/stop API (``/api/v1/chaos``).

The dashboard never talks to the Kubernetes API: the controller is the only component that changes the
cluster. This client only relays the request and turns every failure into a ``ChaosError`` with an HTTP
status the dashboard can pass on (an unreachable controller is 502, never a stale "Running").
"""
from typing import Any, Dict, List, Optional

import requests

from src.dashboard.live_state import _controller_base


class ChaosError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ChaosClient:
    def __init__(self, controller_url: str, token: Optional[str] = None, timeout: float = 5.0):
        self.base = _controller_base(controller_url)  # accepts the brain-style .../api/v1/reconcile URL too
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, **kwargs: Any) -> Any:
        if not self.base:
            raise ChaosError(502, "controller URL is not configured (set GO_CONTROLLER_URL)")
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            resp = requests.request(method, f"{self.base}/api/v1/chaos", headers=headers, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            raise ChaosError(502, f"controller unreachable: {e}") from e
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error") or resp.text
            except (ValueError, AttributeError):
                detail = resp.text
            raise ChaosError(resp.status_code, str(detail)[:300])
        return resp.json()

    def list(self) -> List[Dict[str, Any]]:
        return self._request("GET").get("scenarios", [])

    def set(self, scenario: str, state: str, ttl_minutes: Optional[int] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"scenario": scenario, "state": state}
        if ttl_minutes is not None:
            body["ttl_minutes"] = ttl_minutes
        return self._request("POST", json=body)
