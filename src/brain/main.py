import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.brain.diagnostic_engine import DiagnosticEngine
from src.guardrails.validator import GuardrailEngine
from src.controller.executor import ActionExecutor
from src.controller.api import router as controller_router
from src.brain.notifications import EscalationNotifier
from src.db.database import init_db, db_health

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis-brain-api")

app = FastAPI(
    title="Aegis-SRE Diagnostic Brain",
    description="Phase 3–4 Diagnostic Brain: Alert → RAG → LLM → Guardrails (DB-backed)",
    version="1.5.0",
)

app.include_router(controller_router)

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


class IncidentRequest(BaseModel):
    pod_name: Optional[str] = "aegis-storefront-prod"
    alert_type: Optional[str] = "HTTP_500_SPIKE"


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
    path = (labels.get("aegis_path") or "").strip().lower()
    if name == "AegisHighPodCPU" or "cpu" in name.lower():
        return "AegisHighPodCPU"
    if "oom" in name.lower() or "memory" in name.lower():
        return "OOM_KILLED_RISK"
    if path == "attack" or "falco" in name.lower() or "shell" in name.lower():
        return "falco_shell_spawn"
    summary = (annotations.get("summary") or "") + " " + (annotations.get("description") or "")
    if "t1059" in summary.lower() or "shell" in summary.lower():
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


@app.post("/api/v1/diagnose")
async def diagnose_incident(req: IncidentRequest):
    """Triggers AI investigation and returns JSON Diagnostic Verdict."""
    try:
        verdict = diagnostic_engine.diagnose_incident(
            pod_name=req.pod_name,
            alert_type=req.alert_type,
        )
        return {k: v for k, v in verdict.items() if k != "decision_object"}
    except Exception as e:
        logger.error(f"Error during AI diagnosis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/alerts/webhook")
async def alertmanager_webhook(payload: AlertManagerWebhook):
    """
    AlertManager → brain ingest. Diagnoses each firing alert; does not execute (Phase 5).
    """
    results = []
    alerts = payload.alerts or [
        {
            "labels": payload.commonLabels,
            "annotations": payload.commonAnnotations,
            "status": payload.status or "firing",
        }
    ]

    for alert in alerts:
        labels = alert.get("labels") or {}
        annotations = alert.get("annotations") or {}
        status = (alert.get("status") or payload.status or "firing").lower()
        if status == "resolved":
            results.append({"skipped": True, "reason": "resolved", "labels": labels})
            continue

        pod_name = labels.get("pod") or labels.get("pod_name") or "unknown-pod"
        alert_type = _alert_type_from_labels(labels, annotations)
        try:
            verdict = diagnostic_engine.diagnose_incident(pod_name=pod_name, alert_type=alert_type)
            clean = {k: v for k, v in verdict.items() if k != "decision_object"}
            results.append({"pod_name": pod_name, "alert_type": alert_type, "verdict": clean})
            logger.info(
                "Webhook diagnosis %s/%s -> %s %s",
                pod_name,
                alert_type,
                clean.get("problem_type"),
                clean.get("recommended_action"),
            )
        except Exception as e:
            logger.error(f"Webhook diagnosis failed for {pod_name}: {e}")
            results.append({"pod_name": pod_name, "alert_type": alert_type, "error": str(e)})

    return {"received": len(alerts), "diagnoses": results}


@app.post("/api/v1/remediate")
async def remediate_incident(req: IncidentRequest):
    """
    Full pipeline retained for later phases. Phase 3 success criteria use /diagnose + webhook.
    Executor remains dry-run unless AEGIS_DRY_RUN=false.
    """
    try:
        verdict = diagnostic_engine.diagnose_incident(
            pod_name=req.pod_name,
            alert_type=req.alert_type,
        )
        decision = verdict.get("decision_object")
        exec_result = action_executor.execute_decision(decision)

        escalation_info = None
        if not decision.approved:
            escalation_info = escalation_notifier.dispatch_escalation(decision, verdict)

        verdict_clean = {k: v for k, v in verdict.items() if k != "decision_object"}
        return {
            "pipeline_status": "COMPLETED",
            "verdict": verdict_clean,
            "guardrail_validation": {
                "approved": decision.approved,
                "final_action": decision.final_action,
                "state": decision.state,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "mitre_technique": decision.mitre_technique,
            },
            "execution_result": exec_result.to_dict(),
            "escalation_notification": escalation_info,
        }
    except Exception as e:
        logger.error(f"Error during autonomous remediation pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8001")))
