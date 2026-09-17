import time
from sqlalchemy import Column, Integer, String, Float, Boolean, Text
from src.db.database import Base

class IncidentRecord(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), index=True, nullable=False)
    target_pod = Column(String(128), index=True, nullable=False)
    problem_type = Column(String(64), nullable=False)
    threat_level = Column(String(32), default="MEDIUM")
    mitre_technique = Column(String(64), nullable=True)
    root_cause = Column(Text, nullable=True)
    recommended_action = Column(String(64), nullable=False)
    final_action = Column(String(64), nullable=False)
    confidence = Column(Float, default=1.0)
    guardrail_approved = Column(Boolean, default=True)
    guardrail_reason = Column(Text, nullable=True)
    status = Column(String(32), default="OPEN")
    created_at = Column(String(32), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "target_pod": self.target_pod,
            "problem_type": self.problem_type,
            "threat_level": self.threat_level,
            "mitre_technique": self.mitre_technique,
            "root_cause": self.root_cause,
            "recommended_action": self.recommended_action,
            "final_action": self.final_action,
            "confidence": self.confidence,
            "guardrail_approved": self.guardrail_approved,
            "guardrail_reason": self.guardrail_reason,
            "status": self.status,
            "created_at": self.created_at
        }


class QuarantineRecord(Base):
    __tablename__ = "quarantines"

    id = Column(Integer, primary_key=True, index=True)
    target_pod = Column(String(128), unique=True, index=True, nullable=False)
    namespace = Column(String(64), default="default")
    mitre_technique = Column(String(64), nullable=True)
    trigger_reason = Column(Text, nullable=True)
    forensics_file = Column(String(256), nullable=True)
    policy_yaml = Column(Text, nullable=True)
    quarantined_at = Column(String(32), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "target_pod": self.target_pod,
            "namespace": self.namespace,
            "mitre_technique": self.mitre_technique,
            "trigger_reason": self.trigger_reason,
            "forensics_file": self.forensics_file,
            "quarantined_at": self.quarantined_at,
            "active": self.active
        }


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String(32), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    target_pod = Column(String(128), index=True, nullable=False)
    problem_type = Column(String(64), nullable=False)
    executed_action = Column(String(64), nullable=False)
    execution_success = Column(Boolean, default=True)
    status_code = Column(String(64), default="COMPLETED")
    details = Column(Text, nullable=True)
    forensics_file = Column(String(256), nullable=True)
    health_verified = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "target_pod": self.target_pod,
            "problem_type": self.problem_type,
            "executed_action": self.executed_action,
            "execution_success": self.execution_success,
            "status_code": self.status_code,
            "details": self.details,
            "forensics_file": self.forensics_file,
            "health_verified": self.health_verified
        }


class RestartEventRecord(Base):
    """Sliding-window restart timestamps for guardrail rate limiting (survives process restart)."""
    __tablename__ = "restart_events"

    id = Column(Integer, primary_key=True, index=True)
    target_pod = Column(String(128), index=True, nullable=False)
    recorded_at = Column(Float, index=True, nullable=False)
    created_at = Column(String(32), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self):
        return {
            "id": self.id,
            "target_pod": self.target_pod,
            "recorded_at": self.recorded_at,
            "created_at": self.created_at,
        }


class GuardrailDecisionRecord(Base):
    """Persisted guardrail audit trail for every validate_verdict decision."""
    __tablename__ = "guardrail_decisions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String(32), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    approved = Column(Boolean, default=False)
    final_action = Column(String(64), nullable=False)
    original_action = Column(String(64), nullable=False)
    target_pod = Column(String(128), index=True, nullable=False)
    problem_type = Column(String(64), nullable=False)
    state = Column(String(64), nullable=False)
    reason = Column(Text, nullable=True)
    confidence = Column(Float, default=0.0)
    mitre_technique = Column(String(64), nullable=True)
    rate_limit_exceeded = Column(Boolean, default=False)
    schema_valid = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "approved": self.approved,
            "final_action": self.final_action,
            "original_action": self.original_action,
            "target_pod": self.target_pod,
            "problem_type": self.problem_type,
            "state": self.state,
            "reason": self.reason,
            "confidence": self.confidence,
            "mitre_technique": self.mitre_technique,
            "rate_limit_exceeded": self.rate_limit_exceeded,
            "schema_valid": self.schema_valid,
        }
