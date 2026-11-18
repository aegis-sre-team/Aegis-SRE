"""Phase 6 immune response: alert -> diagnose -> guard -> act -> verify -> escalate.

``process_alert`` is the single orchestration path used by the AlertManager webhook (when
AEGIS_AUTO_REMEDIATE=true) and by ``POST /api/v1/remediate``. Anything that needs a human
(unapproved decision, failed execution, failed verification, an explicit ESCALATE) ends in the
escalation notifier; nothing is ever reported as healed unless verification said so.
"""
import dataclasses
import hmac
import logging
import re
import threading
import time
from typing import Any, Dict, Optional

from src.db.escalations import mark_escalated
from src.guardrails.action_schema import GuardrailDecision, STATE_ESCALATE_HUMAN, is_valid_k8s_name  # noqa: F401 (re-exported)

logger = logging.getLogger("aegis-remediation")


def token_matches(headers, expected: str) -> bool:
    """Constant-time check of `X-Aegis-Token: <t>` or `Authorization: Bearer <t>` against `expected`."""
    supplied = headers.get("x-aegis-token", "")
    if not supplied:
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:]
    return hmac.compare_digest(supplied.encode(), expected.encode())


class AlertDebouncer:
    """Drops repeats of the same alert key inside a window, so a pod that keeps misbehaving (a
    looping shell, a flapping CPU alert) does not trigger an LLM call and an action every second.

    Thread-safe (the API handlers run on a thread pool), bounded (stale keys are pruned), and
    ``release`` lets a caller undo the claim when handling failed so a retry is not suppressed."""

    MAX_KEYS = 1000
    MAX_AGE_S = 3600.0

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._seen = {}
        self._lock = threading.Lock()

    def allow(self, key: str, window_s: float) -> bool:
        with self._lock:
            now = self._clock()
            last = self._seen.get(key)
            if window_s > 0 and last is not None and (now - last) < window_s:
                return False
            self._seen[key] = now
            if len(self._seen) > self.MAX_KEYS:
                self._seen = {k: t for k, t in self._seen.items() if now - t <= self.MAX_AGE_S}
            return True

    def release(self, key: str) -> None:
        with self._lock:
            self._seen.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


def _decision_dict(decision: GuardrailDecision) -> Dict[str, Any]:
    return {
        "approved": decision.approved,
        "final_action": decision.final_action,
        "state": decision.state,
        "reason": decision.reason,
        "confidence": decision.confidence,
        "original_action": decision.original_action,
        "mitre_technique": decision.mitre_technique,
        "namespace": decision.namespace,
    }


def process_alert(engine, executor, notifier, pod_name: str, alert_type: str,
                  namespace: Optional[str] = None, trusted_signal: bool = False) -> Dict[str, Any]:
    verdict = engine.diagnose_incident(pod_name=pod_name, alert_type=alert_type, namespace=namespace,
                                       trusted_signal=trusted_signal)
    decision: Optional[GuardrailDecision] = verdict.get("decision_object")
    clean_verdict = {k: v for k, v in verdict.items() if k != "decision_object"}

    execution = None
    verified = False
    escalation_reason: Optional[str] = None

    if decision is None:
        escalation_reason = "No guardrail decision was produced for this incident."
    elif not decision.approved:
        escalation_reason = decision.reason
    elif decision.final_action == "ESCALATE":
        escalation_reason = decision.reason or "The diagnosis requires a human operator."
    else:
        execution = executor.execute_decision(decision)
        if not execution.success:
            escalation_reason = f"Execution failed ({execution.status_code}): {execution.details}"
        elif execution.health_verified is False or execution.health_verified is None:
            escalation_reason = (
                f"Post-remediation verification failed for {decision.final_action} on "
                f"{decision.target_pod}: the workload did not reach a healthy state."
            )
        else:
            verified = True

    escalation = None
    if escalation_reason is not None:
        base = decision or GuardrailDecision(
            approved=False, final_action="ESCALATE", state=STATE_ESCALATE_HUMAN, reason=escalation_reason,
            confidence=0.0, original_action=str(verdict.get("recommended_action", "UNKNOWN")),
            target_pod=pod_name, problem_type=str(verdict.get("problem_type", "UNKNOWN")), namespace=namespace,
        )
        escalate_decision = dataclasses.replace(
            base, approved=False, final_action="ESCALATE", state=STATE_ESCALATE_HUMAN, reason=escalation_reason,
            original_action=base.original_action,
        )
        escalation = notifier.dispatch_escalation(escalate_decision, clean_verdict)
        # The shared database is how a human sees this on the dashboard's Review page.
        mark_escalated(clean_verdict, escalation_reason)
        logger.warning("ESCALATED %s/%s: %s", namespace, pod_name, escalation_reason)

    dry_run = bool(getattr(executor, "dry_run_mode", False))
    return {
        "verdict": clean_verdict,
        "decision": _decision_dict(decision) if decision else None,
        "execution": execution.to_dict() if execution else None,
        # A dry run changed nothing, so nothing was verified: None, never True.
        "verified": None if (dry_run and verified) else verified,
        "dry_run": dry_run,
        "escalated": escalation_reason is not None,
        "escalation": escalation,
    }
