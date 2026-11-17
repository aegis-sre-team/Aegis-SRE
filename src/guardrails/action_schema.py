import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Tuple

from pydantic import BaseModel, Field, ValidationError, field_validator

# Allowed autonomous actions — must match knowledge base + executor + Go controller
ALLOWED_ACTIONS: Set[str] = {
    "RESTART_POD",
    "SCALE_DEPLOYMENT",
    "CILIUM_QUARANTINE_EBPF",
    "UNQUARANTINE_POD",
    "ESCALATE",
}

# Catastrophic actions blocklist - NEVER allowed autonomously
CATASTROPHIC_BLOCKLIST: Set[str] = {
    "DELETE_NAMESPACE",
    "DELETE_NODE",
    "PURGE_STORAGE",
    "FLUSH_CLUSTER",
    "DISABLE_SECURITY_LOGGING",
}

# Namespaces the autonomous system must never mutate (platform, security and Aegis itself).
PROTECTED_NAMESPACES: Set[str] = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "aegis-system",
    "monitoring",
    "cilium-secrets",
}

# Non-linear State Machine Pipeline states (arXiv:2506.02490 StateGraph RCA)
STATE_ALERT_FIRED = "STATE_ALERT_FIRED"
STATE_EVIDENCE_FETCHED = "STATE_EVIDENCE_FETCHED"
STATE_LLM_DIAGNOSED = "STATE_LLM_DIAGNOSED"
STATE_GUARDRAIL_CHK = "STATE_GUARDRAIL_CHK"
STATE_GUARDRAIL_APPROVED = "STATE_GUARDRAIL_APPROVED"
STATE_ACTION_REJECTED = "STATE_ACTION_REJECTED"
STATE_ESCALATE_HUMAN = "STATE_ESCALATE_HUMAN"


_DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")


def is_valid_k8s_name(name) -> bool:
    """True for a plausible Kubernetes pod/namespace name (DNS-1123, max 253 chars).

    Names arrive from the network (Falco, AlertManager, API bodies) and end up in queries, kubectl
    arguments and file paths, so anything else is rejected before it is used.
    """
    return isinstance(name, str) and len(name) <= 253 and bool(_DNS1123.match(name))


_REPLICASET_POD = re.compile(r"^(?P<w>.+)-[a-z0-9]{8,10}-[a-z0-9]{5}$")
_STATEFULSET_POD = re.compile(r"^(?P<w>.+)-\d+$")


def workload_key(namespace: Optional[str], pod_name: str) -> str:
    """Identity used for the restart budget: the workload that keeps replacing the pod, not the pod.

    A rollout restart gives the pod a new name every time, so a budget keyed by pod name never fills.
    ReplicaSet pods (`web-<hash>-<suffix>`) and StatefulSet pods (`db-0`) collapse to their workload.
    """
    name = pod_name or ""
    m = _REPLICASET_POD.match(name) or _STATEFULSET_POD.match(name)
    workload = m.group("w") if m else name
    key = f"{namespace or '-'}/{workload}"
    if len(key) > 120:  # restart_events.target_pod is String(128)
        key = key[:100] + "-" + hashlib.sha1(key.encode()).hexdigest()[:10]
    return key


class LLMVerdictSchema(BaseModel):
    """
    Schema for LLM diagnostic verdicts before guardrail policy checks / controller.
    Extra fields (reasoning, sensor_health, …) are allowed and ignored here.
    """

    model_config = {"extra": "allow"}

    target_pod: str = Field(..., min_length=1)
    recommended_action: str = Field(..., min_length=1)
    problem_type: str = Field(default="UNKNOWN")
    confidence: float = Field(default=0.0)  # missing confidence must never pass the gate
    mitre_technique: Optional[str] = None
    incident_id: Optional[str] = None
    root_cause: Optional[str] = None
    threat_level: Optional[str] = None
    namespace: Optional[str] = None

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, v: Any) -> float:
        if v is None or v == "":
            return 0.0
        if isinstance(v, bool) or not isinstance(v, (int, float, str)):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        try:
            value = float(v)
        except ValueError as e:
            raise ValueError("confidence must be a number between 0.0 and 1.0") from e
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return value

    @field_validator("recommended_action", "target_pod", "problem_type", mode="before")
    @classmethod
    def _strip_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip()
        return v


class ControllerDecisionSchema(BaseModel):
    """Schema enforced at the controller boundary before any cluster mutation."""

    approved: bool
    final_action: str
    state: str
    reason: str
    confidence: float
    original_action: str
    target_pod: str
    problem_type: str
    mitre_technique: Optional[str] = None
    rate_limit_exceeded: bool = False
    namespace: Optional[str] = None

    @field_validator("final_action", "original_action")
    @classmethod
    def _action_must_be_known(cls, v: str) -> str:
        action = (v or "").upper()
        if action not in ALLOWED_ACTIONS and action not in CATASTROPHIC_BLOCKLIST:
            # Catastrophic names may appear as original_action on rejects; final must be allowlisted.
            pass
        return action


def validate_llm_verdict(raw_verdict: dict) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (normalized_dict, None) on success, or (None, error_reason) on schema failure.
    """
    if not isinstance(raw_verdict, dict):
        return None, "Verdict must be a JSON object."
    try:
        parsed = LLMVerdictSchema.model_validate(raw_verdict)
    except ValidationError as e:
        return None, f"Verdict failed schema validation: {e.errors()[0].get('msg', str(e))}"
    data = parsed.model_dump()
    data["recommended_action"] = data["recommended_action"].upper()
    data["problem_type"] = data["problem_type"].upper() if data.get("problem_type") else "UNKNOWN"
    return data, None


def validate_controller_decision(payload: dict) -> Tuple[Optional[ControllerDecisionSchema], Optional[str]]:
    """Validate a GuardrailDecision-shaped payload before controller execution."""
    try:
        parsed = ControllerDecisionSchema.model_validate(payload)
    except ValidationError as e:
        return None, f"Controller decision failed schema validation: {e.errors()[0].get('msg', str(e))}"

    if parsed.final_action not in ALLOWED_ACTIONS:
        return None, f"final_action '{parsed.final_action}' is not in ALLOWED_ACTIONS."

    if parsed.approved and parsed.state != STATE_GUARDRAIL_APPROVED:
        return None, "Approved decisions must have state STATE_GUARDRAIL_APPROVED."

    if parsed.approved and parsed.final_action == "ESCALATE":
        # Escalate is allowed as an action but should not be auto-executed as a cluster mutate.
        pass

    return parsed, None


@dataclass
class GuardrailDecision:
    """
    Data model for the validated Guardrail Decision.
    """

    approved: bool
    final_action: str
    state: str
    reason: str
    confidence: float
    original_action: str
    target_pod: str
    problem_type: str
    mitre_technique: Optional[str] = None
    rate_limit_exceeded: bool = False
    schema_valid: bool = True
    namespace: Optional[str] = None
