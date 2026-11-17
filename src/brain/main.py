import logging
import os
import re
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from src.brain.diagnostic_engine import DiagnosticEngine
from src.guardrails.validator import GuardrailEngine
from src.controller.executor import ActionExecutor
from src.controller.api import router as controller_router
from src.brain.notifications import EscalationNotifier
from src.brain.remediation import AlertDebouncer, is_valid_k8s_name, process_alert, token_matches
from src.db.database import init_db, db_health

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis-brain-api")

app = FastAPI(
    title="Aegis-SRE Diagnostic Brain",
    description="Phase 3–4 Diagnostic Brain: Alert → RAG → LLM → Guardrails (DB-backed)",
    version="1.5.0",
)


try:
    init_db()
    logger.info("Database initialized for guardrail persistence")
except Exception as e:
    logger.warning("Database init deferred/failed at import: %s", e)

guardrail_engine = GuardrailEngine()
diagnostic_engine = DiagnosticEngine(
    prometheus_url=os.getenv("PROMETHEUS_URL", "http://prometheus.monitoring.svc:9090"),
    loki_url=os.getenv("LOKI_URL", "http://loki.monitoring.svc:3100"),
    guardrail=guardrail_engine,
)
# Phase 5 owns live execution; keep dry-run here.
action_executor = ActionExecutor(dry_run_mode=os.getenv("AEGIS_DRY_RUN", "true").lower() != "false")
escalation_notifier = EscalationNotifier()
alert_debouncer = AlertDebouncer()


def _check_ingest_token(request: Request) -> None:
    """Optional shared-secret guard for every endpoint that can trigger diagnosis or action.

    Off unless AEGIS_INGEST_TOKEN is set. Accepts `X-Aegis-Token: <t>` or `Authorization: Bearer <t>`.
    """
    expected = os.getenv("AEGIS_INGEST_TOKEN", "")
    if expected and not token_matches(request.headers, expected):
        raise HTTPException(status_code=401, detail="missing or invalid ingest token")


# The controller router (/api/v1/controller/*) accepts a self-asserted "approved" decision, so it gets
# the same guard as every other action endpoint.
app.include_router(controller_router, dependencies=[Depends(_check_ingest_token)])


_ALERT_TYPE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class IncidentRequest(BaseModel):
    pod_name: Optional[str] = "aegis-storefront-prod"
    alert_type: Optional[str] = "HTTP_500_SPIKE"
    namespace: Optional[str] = None

    # These values reach queries, kubectl arguments and file names, so they are validated at the edge.
    @field_validator("pod_name", "namespace")
    @classmethod
    def _valid_k8s_name(cls, v):
        if v is not None and not is_valid_k8s_name(v):
            raise ValueError("must be a valid Kubernetes name (lowercase DNS-1123, max 253 chars)")
        return v

    @field_validator("alert_type")
    @classmethod
    def _valid_alert_type(cls, v):
        if v is not None and not _ALERT_TYPE.match(v):
            raise ValueError("alert_type may only contain letters, digits and _ . : - (max 64)")
        return v


class AlertManagerWebhook(BaseModel):
    version: Optional[str] = None
    status: Optional[str] = None
    receiver: Optional[str] = None
    groupLabels: Dict[str, Any] = Field(default_factory=dict)
    commonLabels: Dict[str, Any] = Field(default_factory=dict)
    commonAnnotations: Dict[str, Any] = Field(default_factory=dict)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)


def _alert_type_from_labels(labels: Dict[str, Any], annotations: Dict[str, Any]) -> str:
    name = (labels.get("alertname") or "").strip()
    lowered = name.lower()
    path = (labels.get("aegis_path") or "").strip().lower()
    # Decide from the alert RULE (name / path label) only. Free text such as the summary contains pod
    # names, and a pod called "...shell..." must never turn a CPU or crash alert into a security one
    # (security alerts get a forced quarantine downstream).
    if "crashloop" in lowered:
        return "CRASHLOOP_BACKOFF"
    if name == "AegisHighPodCPU" or "cpu" in lowered:
        return "AegisHighPodCPU"
    if "oom" in lowered or "memory" in lowered:
        return "OOM_KILLED_RISK"
    if path == "attack" or "falco" in lowered:
        return "falco_shell_spawn"
    return name or "UNKNOWN_ALERT"


@app.get("/health")
async def health_check():
    sensors = diagnostic_engine.collector.check_sensors()
    critical_ok = not diagnostic_engine.collector.any_critical_dark()
    db = db_health()
    return {
        "status": "healthy" if critical_ok else "degraded",
        "service": "aegis-diagnostic-brain",
        "version": "1.5.0",
        "rag_docs_indexed": len(diagnostic_engine.rag.documents),
        "sensors": sensors,
        "fail_closed": True,
        "database": db,
        "guardrails": {
            "persist": guardrail_engine.persist,
            "min_confidence": guardrail_engine.min_confidence_threshold,
            "max_restarts_per_hour": guardrail_engine.max_restarts_per_hour,
        },
        "dry_run": os.getenv("AEGIS_DRY_RUN", "true").lower() != "false",
    }


@app.get("/api/v1/sensors")
async def sensor_status():
    return diagnostic_engine.collector.check_sensors()


@app.post("/api/v1/diagnose", dependencies=[Depends(_check_ingest_token)])
def diagnose_incident(req: IncidentRequest):
    """Triggers AI investigation and returns JSON Diagnostic Verdict."""
    try:
        verdict = diagnostic_engine.diagnose_incident(
            pod_name=req.pod_name,
            alert_type=req.alert_type,
            namespace=req.namespace,
            reserve_budget=False,  # a diagnosis is not a restart
        )
        return {k: v for k, v in verdict.items() if k != "decision_object"}
    except Exception as e:
        logger.error(f"Error during AI diagnosis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _handle_alert(pod_name: str, namespace: Optional[str], alert_type: str,
                  trusted_signal: bool = False) -> Dict[str, Any]:
    """Diagnose one alert; with AEGIS_AUTO_REMEDIATE=true also guard, act, verify and escalate."""
    base = {"pod_name": pod_name, "namespace": namespace, "alert_type": alert_type}
    try:
        if os.getenv("AEGIS_AUTO_REMEDIATE", "false").lower() == "true":
            rem = process_alert(
                diagnostic_engine, action_executor, escalation_notifier,
                pod_name=pod_name, alert_type=alert_type, namespace=namespace, trusted_signal=trusted_signal,
            )
            return {**base, "verdict": rem["verdict"],
                    "remediation": {k: rem.get(k) for k in ("decision", "execution", "verified", "dry_run", "escalated", "escalation")}}
        # Diagnosis only: look, do not spend the restart budget.
        verdict = diagnostic_engine.diagnose_incident(
            pod_name=pod_name, alert_type=alert_type, namespace=namespace,
            reserve_budget=False, trusted_signal=trusted_signal,
        )
        clean = {k: v for k, v in verdict.items() if k != "decision_object"}
        logger.info("Diagnosis %s/%s [%s] -> %s %s", namespace, pod_name, alert_type,
                    clean.get("problem_type"), clean.get("recommended_action"))
        return {**base, "verdict": clean}
    except Exception as e:
        logger.error("Alert handling failed for %s/%s: %s", namespace, pod_name, e)
        return {**base, "error": str(e)}


def _run_alert_in_background(key: str, pod_name: str, namespace: Optional[str], alert_type: str) -> None:
    """Background worker for auto-remediation. A failed run releases the debounce claim so a retry works."""
    result = _handle_alert(pod_name, namespace, alert_type, trusted_signal=True)
    if "error" in result:
        alert_debouncer.release(key)


@app.post("/api/v1/alerts/webhook", dependencies=[Depends(_check_ingest_token)])
def alertmanager_webhook(payload: AlertManagerWebhook, background: BackgroundTasks):
    """
    AlertManager -> brain ingest. By default each firing alert is only diagnosed (synchronously, the
    verdict is in the response). With AEGIS_AUTO_REMEDIATE=true the pipeline runs in the background and
    this returns immediately, because acting plus verifying can take minutes and AlertManager's webhook
    would time out and retry (duplicate actions). Repeats are debounced.
    """
    results = []
    alerts = payload.alerts or [
        {
            "labels": payload.commonLabels,
            "annotations": payload.commonAnnotations,
            "status": payload.status or "firing",
        }
    ]
    auto = os.getenv("AEGIS_AUTO_REMEDIATE", "false").lower() == "true"
    window = float(os.getenv("AEGIS_ALERT_DEBOUNCE_S", "30"))

    for alert in alerts:
        labels = alert.get("labels") or {}
        annotations = alert.get("annotations") or {}
        status = (alert.get("status") or payload.status or "firing").lower()
        if status == "resolved":
            results.append({"skipped": True, "reason": "resolved", "labels": labels})
            continue

        pod_name = labels.get("pod") or labels.get("pod_name") or "unknown-pod"
        namespace = labels.get("namespace") or None
        if not is_valid_k8s_name(pod_name) or (namespace is not None and not is_valid_k8s_name(namespace)):
            logger.warning("Ignoring alert with an invalid pod/namespace name")
            results.append({"skipped": True, "reason": "invalid pod or namespace name"})
            continue
        alert_type = _alert_type_from_labels(labels, annotations)

        if not auto:
            results.append(_handle_alert(pod_name, namespace, alert_type, trusted_signal=True))
            continue
        key = f"{namespace}/{pod_name}/{labels.get('alertname', '')}"
        base = {"pod_name": pod_name, "namespace": namespace, "alert_type": alert_type}
        if not alert_debouncer.allow(key, window):
            results.append({**base, "debounced": True})
            continue
        background.add_task(_run_alert_in_background, key, pod_name, namespace, alert_type)
        results.append({**base, "accepted": True})

    return {"received": len(alerts), "diagnoses": results}


FALCO_RULE_ALERT_TYPES = {
    "Aegis Shell Spawned in Container": "falco_shell_spawn",
    "Aegis Sensitive File Read": "falco_sensitive_file_read",
    "Aegis Network Discovery Tool Spawned": "falco_network_recon",
}


class FalcoEvent(BaseModel):
    """Subset of Falco's json_output / http_output payload that the brain needs."""
    model_config = {"extra": "allow"}

    rule: str = ""
    priority: Optional[str] = None
    output: Optional[str] = None
    output_fields: Dict[str, Any] = Field(default_factory=dict)


@app.post("/api/v1/alerts/falco", dependencies=[Depends(_check_ingest_token)])
def falco_ingest(ev: FalcoEvent, background: BackgroundTasks):
    """
    Falco (http_output) -> brain. Only Aegis rules that name a valid pod in a MANAGED namespace are
    acted on; repeats for the same pod+rule inside AEGIS_ALERT_DEBOUNCE_S (default 30) are dropped.
    Anything else is ignored before any LLM call or notification (Falco sees the whole cluster).
    """
    if not ev.rule.startswith("Aegis "):
        return {"ignored": True, "reason": "not an Aegis rule"}
    pod = str(ev.output_fields.get("k8s.pod.name") or "").strip()
    namespace = str(ev.output_fields.get("k8s.ns.name") or "").strip()
    if pod in ("", "<NA>") or namespace in ("", "<NA>"):
        return {"ignored": True, "reason": "event has no pod/namespace identity"}
    if not is_valid_k8s_name(pod) or not is_valid_k8s_name(namespace):
        logger.warning("Ignoring Falco event with an invalid pod/namespace name")
        return {"ignored": True, "reason": "invalid pod or namespace name"}
    violation = GuardrailEngine.namespace_violation(namespace, "RESTART_POD")
    if violation:
        logger.info("Ignoring Falco event outside the managed namespaces: %s", violation)
        return {"ignored": True, "reason": f"namespace not managed: {violation}"}

    slug = "".join(c if c.isalnum() else "_" for c in ev.rule[len("Aegis "):].lower()).strip("_")
    alert_type = FALCO_RULE_ALERT_TYPES.get(ev.rule, f"falco_{slug}")

    window = float(os.getenv("AEGIS_ALERT_DEBOUNCE_S", "30"))
    key = f"{namespace}/{pod}/{alert_type}"
    if not alert_debouncer.allow(key, window):
        return {"debounced": True, "pod_name": pod, "namespace": namespace, "alert_type": alert_type}

    if os.getenv("AEGIS_AUTO_REMEDIATE", "false").lower() == "true":
        background.add_task(_run_alert_in_background, key, pod, namespace, alert_type)
        return {"accepted": True, "pod_name": pod, "namespace": namespace, "alert_type": alert_type}
    result = _handle_alert(pod, namespace, alert_type, trusted_signal=True)
    if "error" in result:
        alert_debouncer.release(key)
    return {"received": 1, "result": result}


@app.post("/api/v1/remediate", dependencies=[Depends(_check_ingest_token)])
def remediate_incident(req: IncidentRequest):
    """
    Full pipeline: diagnose -> guardrails -> execute -> verify -> escalate on any failure.
    The executor stays dry-run unless AEGIS_DRY_RUN=false.
    """
    try:
        rem = process_alert(
            diagnostic_engine, action_executor, escalation_notifier,
            pod_name=req.pod_name, alert_type=req.alert_type, namespace=req.namespace,
        )
        decision = rem["decision"] or {}
        return {
            "pipeline_status": "COMPLETED",
            "verdict": rem["verdict"],
            "guardrail_validation": {k: decision.get(k) for k in
                                     ("approved", "final_action", "state", "reason", "confidence", "mitre_technique", "namespace")},
            "execution_result": rem["execution"],
            "verified": rem["verified"],
            "dry_run": rem.get("dry_run"),
            "escalated": rem["escalated"],
            "escalation_notification": rem["escalation"],
        }
    except Exception as e:
        logger.error(f"Error during autonomous remediation pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8001")))
