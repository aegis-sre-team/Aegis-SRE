import logging
from typing import Any, Dict, Optional

from src.brain.collector import SensorDarkError, TelemetryCollector
from src.brain.metric_serializer import MetricSerializer
from src.brain.rag_engine import RAGEngine
from src.brain.llm_client import LLMClient
from src.brain.prompt_templates import SYSTEM_DIAGNOSTIC_PROMPT, USER_EVIDENCE_PROMPT_TEMPLATE
from src.guardrails import GuardrailEngine

logger = logging.getLogger("aegis-brain-engine")


class DiagnosticEngine:
    """
    Core AI Diagnostic Orchestrator (Phase 3 + Phase 4 guardrails).
    Coordinates Telemetry Collection, Metric Serialization, RAG Retrieval,
    LLM Inference, then DB-backed GuardrailEngine validation before any controller handoff.
    """

    def __init__(
        self,
        prometheus_url: Optional[str] = None,
        loki_url: Optional[str] = None,
        knowledge_base_dir: Optional[str] = None,
        guardrail: Optional[GuardrailEngine] = None,
    ):
        self.collector = TelemetryCollector(
            prometheus_url=prometheus_url,
            loki_url=loki_url,
        )
        self.rag = RAGEngine(knowledge_base_dir=knowledge_base_dir)
        self.llm = LLMClient()
        self.guardrail = guardrail or GuardrailEngine()

    def _escalate_dark(self, pod_name: str, alert_type: str, dark_detail: str) -> dict:
        """Fail closed when sensors cannot be trusted."""
        import time

        verdict = {
            "incident_id": f"INC-DARK-{int(time.time())}",
            "target_pod": pod_name,
            "problem_type": "SENSOR_DARK",
            "threat_level": "HIGH",
            "mitre_technique": None,
            "root_cause": f"Telemetry sensors dark or unreachable: {dark_detail}",
            "recommended_action": "ESCALATE",
            "confidence": 0.0,
            "reasoning": (
                "Fail-closed: refusing to invent healthy metrics or fake Falco events. "
                f"Alert '{alert_type}' on '{pod_name}' requires human escalation until sensors recover."
            ),
            "_ai_provider": "FailClosed-SensorDark",
            "sensor_health": self.collector.sensor_health,
        }
        decision = self.guardrail.validate_verdict(verdict)
        verdict["decision_object"] = decision
        verdict["guardrail_validation"] = {
            "approved": decision.approved,
            "final_action": decision.final_action,
            "state": decision.state,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "original_action": decision.original_action,
            "rate_limit_exceeded": decision.rate_limit_exceeded,
            "schema_valid": decision.schema_valid,
        }
        verdict["recommended_action"] = decision.final_action
        return verdict

    def diagnose_incident(
        self,
        pod_name: str = "aegis-target-app",
        alert_type: str = "HTTP_500_SPIKE",
        fail_closed: bool = True,
    ) -> dict:
        """
        Executes end-to-end AI diagnosis pipeline for an incident and validates output through Guardrails.
        """
        logger.info(f"Starting AI Diagnosis for pod '{pod_name}' (Alert: {alert_type})...")

        self.collector.check_sensors()
        if fail_closed and self.collector.any_critical_dark():
            detail = str(self.collector.sensor_health)
            logger.error(f"Sensors dark — escalating: {detail}")
            return self._escalate_dark(pod_name, alert_type, detail)

        alert_l = (alert_type or "").lower()
        security_context = any(
            token in alert_l
            for token in (
                "falco",
                "shell",
                "t1059",
                "t1552",
                "security",
                "attack",
            )
        )

        try:
            raw_metrics = self.collector.fetch_prometheus_metrics(pod_name)
            loki_logs = self.collector.fetch_loki_logs(pod_name)
            falco_events = self.collector.fetch_falco_alerts(
                pod_name,
                security_context=security_context,
            )
        except SensorDarkError as e:
            if fail_closed:
                return self._escalate_dark(pod_name, alert_type, str(e))
            raise

        metric_summary = MetricSerializer.serialize_prometheus_metrics(pod_name, raw_metrics)
        rag_context = self.rag.search_runbooks(f"{alert_type} {pod_name}")

        formatted_logs = "\n".join(loki_logs[-10:]) if loki_logs else "(no log lines returned — sensor OK, empty result)"
        formatted_falco = (
            "\n".join(falco_events)
            if falco_events
            else "No matching Falco events in Loki {app=\"falco\"} for this window."
        )

        user_prompt = USER_EVIDENCE_PROMPT_TEMPLATE.format(
            pod_name=pod_name,
            alert_type=alert_type,
            sensor_health=self.collector.sensor_health,
            metric_summary=metric_summary,
            loki_logs=formatted_logs,
            falco_events=formatted_falco,
            rag_context=rag_context,
        )

        verdict = self.llm.generate_json_diagnosis(SYSTEM_DIAGNOSTIC_PROMPT, user_prompt)
        verdict["target_pod"] = pod_name
        verdict.setdefault("confidence", 0.85)
        verdict["sensor_health"] = self.collector.sensor_health
        verdict["rag_preview"] = rag_context[:500]
        logger.info(
            f"Diagnostic Verdict Generated: {verdict.get('problem_type')} -> "
            f"{verdict.get('recommended_action')} (confidence={verdict.get('confidence')})"
        )

        decision = self.guardrail.validate_verdict(verdict)
        verdict["decision_object"] = decision
        verdict["guardrail_validation"] = {
            "approved": decision.approved,
            "final_action": decision.final_action,
            "state": decision.state,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "original_action": decision.original_action,
            "rate_limit_exceeded": decision.rate_limit_exceeded,
            "schema_valid": decision.schema_valid,
        }
        verdict["recommended_action"] = decision.final_action
        return verdict

    def rag_for_alert(self, alert_type: str, top_k: int = 2) -> str:
        """Expose RAG retrieval for Phase 3 verification."""
        return self.rag.search_runbooks(alert_type, top_k=top_k)
