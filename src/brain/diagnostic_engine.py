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

    def _escalate_dark(
        self, pod_name: str, alert_type: str, dark_detail: str, namespace: Optional[str] = None
    ) -> dict:
        """Fail closed when sensors cannot be trusted."""
        import time

        verdict = {
            "incident_id": f"INC-DARK-{int(time.time())}",
            "target_pod": pod_name,
            "namespace": namespace,
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
        namespace: Optional[str] = None,
        reserve_budget: bool = True,
        trusted_signal: bool = False,
    ) -> dict:
        """
        Executes end-to-end AI diagnosis pipeline for an incident and validates output through Guardrails.
        """
        logger.info(f"Starting AI Diagnosis for pod '{pod_name}' (Alert: {alert_type})...")

        self.collector.check_sensors()
        if fail_closed and self.collector.any_critical_dark():
            detail = str(self.collector.sensor_health)
            logger.error(f"Sensors dark — escalating: {detail}")
            return self._escalate_dark(pod_name, alert_type, detail, namespace)

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
            raw_metrics = self.collector.fetch_prometheus_metrics(pod_name, namespace=namespace)
            loki_logs = self.collector.fetch_loki_logs(pod_name, namespace=namespace)
            falco_events = self.collector.fetch_falco_alerts(
                pod_name,
                security_context=security_context,
                namespace=namespace,
            )
        except SensorDarkError as e:
            if fail_closed:
                return self._escalate_dark(pod_name, alert_type, str(e), namespace)
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
        # The namespace is trusted only from the alert; never from the LLM's output.
        verdict["namespace"] = namespace
        verdict.setdefault("confidence", 0.0)
        if trusted_signal:
            # Only a TRUSTED source (Falco ingest, our AlertManager rules) may force a security verdict;
            # an alert_type string typed into the public API must not.
            verdict = self._apply_trusted_signal_policy(verdict, alert_type)
        verdict["sensor_health"] = self.collector.sensor_health
        verdict["rag_preview"] = rag_context[:500]
        logger.info(
            f"Diagnostic Verdict Generated: {verdict.get('problem_type')} -> "
            f"{verdict.get('recommended_action')} (confidence={verdict.get('confidence')})"
        )

        decision = self.guardrail.validate_verdict(verdict, reserve_budget=reserve_budget)
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

    @staticmethod
    def _apply_trusted_signal_policy(verdict: dict, alert_type: str) -> dict:
        """Deterministic rules beat the LLM when the signal itself is trusted.

        An alert type starting with "falco" means an Aegis Falco rule fired for this pod (kernel-level
        evidence, not workload-supplied text). The model may not talk that down to a routine bug:
        it is a SECURITY_ATTACK and the action is quarantine (or an explicit human escalation).
        """
        if not (alert_type or "").lower().startswith("falco"):
            return verdict
        changed = False
        if verdict.get("problem_type") != "SECURITY_ATTACK":
            verdict["problem_type"] = "SECURITY_ATTACK"
            changed = True
        if verdict.get("recommended_action") not in ("CILIUM_QUARANTINE_EBPF", "ESCALATE"):
            verdict["recommended_action"] = "CILIUM_QUARANTINE_EBPF"
            changed = True
        if changed:
            try:
                confidence = float(verdict.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            verdict["confidence"] = max(confidence, 0.90)
            verdict["_trusted_signal_override"] = True
            verdict["reasoning"] = (
                f"{verdict.get('reasoning', '')} [Policy override: a Falco security rule fired for this pod, so "
                "the verdict is forced to SECURITY_ATTACK / quarantine regardless of the model output.]"
            ).strip()
        return verdict

    def rag_for_alert(self, alert_type: str, top_k: int = 2) -> str:
        """Expose RAG retrieval for Phase 3 verification."""
        return self.rag.search_runbooks(alert_type, top_k=top_k)
