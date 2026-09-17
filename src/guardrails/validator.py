import time
import os
import json
import logging
from typing import Callable, Dict, List, Optional, Tuple

from src.guardrails.action_schema import (
    ALLOWED_ACTIONS,
    CATASTROPHIC_BLOCKLIST,
    GuardrailDecision,
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN,
    validate_llm_verdict,
)

logger = logging.getLogger("aegis-guardrail-validator")


class GuardrailEngine:
    """
    Catastrophic Guardrail & Decision Safety Engine (Phase 4).
    Validates LLM-recommended diagnostic actions before execution.
    Rate limits and audit decisions persist to the configured DATABASE_URL.
    """

    def __init__(
        self,
        min_confidence_threshold: float = 0.70,
        max_restarts_per_hour: int = 3,
        session_factory: Optional[Callable] = None,
        persist: bool = True,
        also_jsonl: bool = True,
    ):
        self.min_confidence_threshold = min_confidence_threshold
        self.max_restarts_per_hour = max_restarts_per_hour
        self.persist = persist
        self.also_jsonl = also_jsonl
        # In-memory fallback when DB is unavailable or persist=False
        self._restart_history: Dict[str, List[float]] = {}
        self._session_factory = session_factory

        if self.persist and self._session_factory is None:
            try:
                from src.db.database import SessionLocal, init_db

                init_db()
                self._session_factory = SessionLocal
            except Exception as e:
                logger.warning("Guardrail DB init failed; using in-memory rate limits: %s", e)
                self.persist = False

    def validate_verdict(self, raw_verdict: dict) -> GuardrailDecision:
        """Validates raw LLM diagnostic verdict against schema + safety rules."""
        raw = raw_verdict if isinstance(raw_verdict, dict) else {}
        normalized, schema_error = validate_llm_verdict(raw)
        if schema_error or normalized is None:
            logger.warning("GUARDRAIL REJECT: Schema validation failed — %s", schema_error)
            decision = GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ACTION_REJECTED,
                reason=schema_error or "Verdict failed schema validation.",
                confidence=float(raw.get("confidence", 0.0) or 0.0),
                original_action=str(raw.get("recommended_action", "UNKNOWN")),
                target_pod=str(raw.get("target_pod", "unknown-pod") or "unknown-pod"),
                problem_type=str(raw.get("problem_type", "UNKNOWN") or "UNKNOWN"),
                mitre_technique=raw.get("mitre_technique"),
                schema_valid=False,
            )
            self._write_audit_log(decision)
            return decision

        decision = self._evaluate_policy(
            target_pod=normalized["target_pod"],
            proposed_action=normalized["recommended_action"],
            problem_type=normalized["problem_type"],
            confidence=float(normalized["confidence"]),
            mitre_technique=normalized.get("mitre_technique"),
        )
        self._write_audit_log(decision)
        return decision

    def _evaluate_policy(
        self,
        target_pod: str,
        proposed_action: str,
        problem_type: str,
        confidence: float,
        mitre_technique: Optional[str],
    ) -> GuardrailDecision:
        """Apply blocklist / allowlist / confidence / rate-limit / attack-override rules."""
        if proposed_action in CATASTROPHIC_BLOCKLIST:
            logger.warning(
                "GUARDRAIL REJECT: Action '%s' is on the CATASTROPHIC BLOCKLIST!",
                proposed_action,
            )
            return GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ACTION_REJECTED,
                reason=f"Action '{proposed_action}' is blocked by catastrophic safety filter.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique,
            )

        if proposed_action not in ALLOWED_ACTIONS:
            logger.warning(
                "GUARDRAIL REJECT: Action '%s' is not in allowed action registry.",
                proposed_action,
            )
            return GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ACTION_REJECTED,
                reason=f"Action '{proposed_action}' is not an allowed autonomous action.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique,
            )

        if confidence < self.min_confidence_threshold:
            logger.warning(
                "GUARDRAIL ESCALATE: Confidence (%.2f) below minimum threshold (%.2f).",
                confidence,
                self.min_confidence_threshold,
            )
            return GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ESCALATE_HUMAN,
                reason=(
                    f"Diagnostic confidence ({confidence:.2f}) is below minimum threshold "
                    f"({self.min_confidence_threshold:.2f}). Human escalation required."
                ),
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique,
            )

        # Attack path: quarantine, never restart (do not consume restart quota)
        if problem_type == "SECURITY_ATTACK" and proposed_action == "RESTART_POD":
            logger.warning(
                "GUARDRAIL OVERRIDE: Restarting pod under active security attack is ineffective. "
                "Forcing CILIUM_QUARANTINE_EBPF."
            )
            return GuardrailDecision(
                approved=True,
                final_action="CILIUM_QUARANTINE_EBPF",
                state=STATE_GUARDRAIL_APPROVED,
                reason=(
                    "Overrode RESTART_POD with CILIUM_QUARANTINE_EBPF because incident "
                    "is categorized as SECURITY_ATTACK."
                ),
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique,
            )

        if proposed_action == "RESTART_POD":
            allowed, _count = self._check_and_record_restart(target_pod)
            if not allowed:
                logger.warning(
                    "GUARDRAIL REJECT: Pod '%s' exceeded restart limit in 1 hour.",
                    target_pod,
                )
                return GuardrailDecision(
                    approved=False,
                    final_action="ESCALATE",
                    state=STATE_ACTION_REJECTED,
                    reason=(
                        f"Pod '{target_pod}' exceeded restart frequency cap. "
                        "Escalated to prevent restart loop."
                    ),
                    confidence=confidence,
                    original_action=proposed_action,
                    target_pod=target_pod,
                    problem_type=problem_type,
                    mitre_technique=mitre_technique,
                    rate_limit_exceeded=True,
                )

        logger.info(
            "GUARDRAIL APPROVE: Action '%s' passed all safety checks for pod '%s'.",
            proposed_action,
            target_pod,
        )
        return GuardrailDecision(
            approved=True,
            final_action=proposed_action,
            state=STATE_GUARDRAIL_APPROVED,
            reason=f"Action '{proposed_action}' passed all safety and rate-limit guardrails.",
            confidence=confidence,
            original_action=proposed_action,
            target_pod=target_pod,
            problem_type=problem_type,
            mitre_technique=mitre_technique,
        )

    def _write_audit_log(self, decision: GuardrailDecision):
        """Persist decision to DB (primary) and optionally JSONL (secondary)."""
        if self.persist and self._session_factory is not None:
            try:
                from src.db.models import GuardrailDecisionRecord

                with self._session_factory() as session:
                    session.add(
                        GuardrailDecisionRecord(
                            approved=decision.approved,
                            final_action=decision.final_action,
                            original_action=decision.original_action,
                            target_pod=decision.target_pod,
                            problem_type=decision.problem_type,
                            state=decision.state,
                            reason=decision.reason,
                            confidence=decision.confidence,
                            mitre_technique=decision.mitre_technique,
                            rate_limit_exceeded=decision.rate_limit_exceeded,
                            schema_valid=decision.schema_valid,
                        )
                    )
                    session.commit()
            except Exception as e:
                logger.error("Error writing guardrail decision to DB: %s", e)

        if not self.also_jsonl:
            return

        try:
            log_dir = os.getenv("AEGIS_DB_DIR", "logs")
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, "guardrail_audit.jsonl")
            log_entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "approved": decision.approved,
                "final_action": decision.final_action,
                "original_action": decision.original_action,
                "target_pod": decision.target_pod,
                "problem_type": decision.problem_type,
                "state": decision.state,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "mitre_technique": decision.mitre_technique,
                "rate_limit_exceeded": decision.rate_limit_exceeded,
                "schema_valid": decision.schema_valid,
            }
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error("Error writing guardrail audit JSONL: %s", e)

    def _check_and_record_restart(self, pod_name: str) -> Tuple[bool, int]:
        """Sliding-window restart rate limit; DB-backed when persist is enabled."""
        now = time.time()
        one_hour_ago = now - 3600

        if self.persist and self._session_factory is not None:
            try:
                from src.db.models import RestartEventRecord

                with self._session_factory() as session:
                    recent = (
                        session.query(RestartEventRecord)
                        .filter(
                            RestartEventRecord.target_pod == pod_name,
                            RestartEventRecord.recorded_at >= one_hour_ago,
                        )
                        .order_by(RestartEventRecord.recorded_at.asc())
                        .all()
                    )
                    count = len(recent)
                    if count >= self.max_restarts_per_hour:
                        return False, count

                    session.add(RestartEventRecord(target_pod=pod_name, recorded_at=now))
                    session.commit()
                    return True, count + 1
            except Exception as e:
                logger.error("DB restart rate-limit failed; falling back to memory: %s", e)

        timestamps = self._restart_history.get(pod_name, [])
        recent_timestamps = [t for t in timestamps if t >= one_hour_ago]
        if len(recent_timestamps) >= self.max_restarts_per_hour:
            self._restart_history[pod_name] = recent_timestamps
            return False, len(recent_timestamps)

        recent_timestamps.append(now)
        self._restart_history[pod_name] = recent_timestamps
        return True, len(recent_timestamps)

    def reset_rate_limits(self, pod_name: Optional[str] = None):
        """Clears rate-limit history (testing). Optionally scoped to one pod."""
        if pod_name:
            self._restart_history.pop(pod_name, None)
        else:
            self._restart_history.clear()

        if self.persist and self._session_factory is not None:
            try:
                from src.db.models import RestartEventRecord

                with self._session_factory() as session:
                    q = session.query(RestartEventRecord)
                    if pod_name:
                        q = q.filter(RestartEventRecord.target_pod == pod_name)
                    q.delete(synchronize_session=False)
                    session.commit()
            except Exception as e:
                logger.error("Failed to reset DB restart events: %s", e)
