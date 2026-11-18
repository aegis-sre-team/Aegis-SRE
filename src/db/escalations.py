"""Escalations ("needs a human") kept in the shared database.

The brain runs in the cluster and the dashboard runs elsewhere; the only thing they share is the
database. An escalation used to exist only in a dashboard-process dict (demo) or a file inside the
brain's pod (live), so the Review page was always empty against a real cluster.

An escalation is an ``IncidentRecord`` with status ``ESCALATED``; resolving it sets ``RESOLVED``.
No schema change: the live Postgres table already exists and ``create_all`` never alters tables.
None of these functions raises: a database problem must never break diagnosis or the dashboard.
"""
import logging
from typing import Any, Dict, List

from src.db import database
from src.db.models import IncidentRecord

logger = logging.getLogger("aegis-escalations")

ESCALATED = "ESCALATED"
RESOLVED = "RESOLVED"


def mark_escalated(verdict: Dict[str, Any], reason: str) -> bool:
    """Record that the incident needs a human. Updates the newest row for the incident id, or creates
    one (the fail-closed SENSOR_DARK path never persists its verdict). Repeat calls keep one row."""
    incident_id = str(verdict.get("incident_id") or "").strip()
    if not incident_id:
        return False
    try:
        database.init_db()
        with database.SessionLocal() as session:
            rec = (session.query(IncidentRecord)
                   .filter(IncidentRecord.incident_id == incident_id)
                   .order_by(IncidentRecord.id.desc()).first())
            if rec is None:
                rec = IncidentRecord(
                    incident_id=incident_id,
                    target_pod=verdict.get("target_pod") or "unknown",
                    problem_type=verdict.get("problem_type") or "UNKNOWN",
                    threat_level=verdict.get("threat_level") or "HIGH",
                    mitre_technique=verdict.get("mitre_technique"),
                    root_cause=verdict.get("root_cause"),
                    recommended_action=verdict.get("recommended_action") or "ESCALATE",
                    confidence=float(verdict.get("confidence") or 0.0),
                )
                session.add(rec)
            rec.final_action = "ESCALATE"
            rec.guardrail_approved = False
            rec.guardrail_reason = reason
            rec.status = ESCALATED
            session.commit()
        return True
    except Exception as e:
        logger.warning("could not record escalation %s: %s", incident_id, e)
        return False


def list_open_escalations(limit: int = 50) -> List[Dict[str, Any]]:
    """Open escalations, newest first, shaped like the UI's ``Escalation`` type."""
    try:
        database.init_db()
        with database.SessionLocal() as session:
            rows = (session.query(IncidentRecord)
                    .filter(IncidentRecord.status == ESCALATED)
                    .order_by(IncidentRecord.id.desc()).limit(limit).all())
            return [{
                "incident_id": r.incident_id,
                "target_pod": r.target_pod,
                "problem_type": r.problem_type,
                "confidence": float(r.confidence) if r.confidence is not None else None,
                "reason": r.guardrail_reason or "",
                "mitre_technique": r.mitre_technique,
                "timestamp": r.created_at,
            } for r in rows]
    except Exception as e:
        logger.warning("could not list escalations: %s", e)
        return []


def resolve_escalation_record(incident_id: str) -> bool:
    """Mark an open escalation resolved. False when there was nothing open under that id."""
    try:
        database.init_db()
        with database.SessionLocal() as session:
            rows = (session.query(IncidentRecord)
                    .filter(IncidentRecord.incident_id == incident_id, IncidentRecord.status == ESCALATED).all())
            for r in rows:
                r.status = RESOLVED
            session.commit()
            return bool(rows)
    except Exception as e:
        logger.warning("could not resolve escalation %s: %s", incident_id, e)
        return False
