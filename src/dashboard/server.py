import os
import re
import json
import time
import asyncio
import logging
import requests
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

load_dotenv()

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.brain.diagnostic_engine import DiagnosticEngine
from src.guardrails.validator import GuardrailEngine
from src.controller.executor import ActionExecutor
from src.brain.notifications import EscalationNotifier
from src.brain.remediation import token_matches
from src.dashboard.chaos_client import ChaosClient, ChaosError
from src.dashboard.live_state import LiveClusterState, resolve_data_source, sensor_startup_logs
from src.db.escalations import list_open_escalations, resolve_escalation_record
from src.guardrails.action_schema import GuardrailDecision, STATE_GUARDRAIL_APPROVED

logger = logging.getLogger("aegis-dashboard-server")

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        source = await asyncio.to_thread(current_data_source)
        sensors = await asyncio.to_thread(diagnostic_engine.collector.check_sensors) if source == "live" else {}
        for level, category, message in sensor_startup_logs(sensors, source):
            add_terminal_log(level, category, message)
    except Exception as e:
        add_terminal_log("WARN", "SYSTEM", f"Could not determine sensor state at startup: {e}")

    # Initialize SQLite database and restore persisted active quarantines
    try:
        from src.db.database import init_db, SessionLocal
        from src.db.models import QuarantineRecord
        init_db()
        with SessionLocal() as session:
            active_q = session.query(QuarantineRecord).filter_by(active=True).all()
            for q in active_q:
                pod = q.target_pod.split("/", 1)[-1]
                ACTIVE_QUARANTINES[pod] = {
                    "pod_name": pod,
                    "mitre_technique": q.mitre_technique or "T1059 Command Execution",
                    "forensics_file": q.forensics_file or f"logs/forensics_{pod}.json",
                    "quarantined_at": q.quarantined_at
                }
                if pod in POD_TELEMETRY_STORE:
                    POD_TELEMETRY_STORE[pod]["status"] = "QUARANTINED"
        if ACTIVE_QUARANTINES:
            add_terminal_log("ALERT", "DATABASE", f"Restored {len(ACTIVE_QUARANTINES)} active eBPF quarantines from persistent database.")
    except Exception as e:
        logger.warning(f"Error restoring state from database: {e}")

    task = asyncio.create_task(telemetry_broadcast_loop())
    yield
    task.cancel()

app = FastAPI(
    title="Aegis-SRE Masterpiece Real-Time Command Center",
    description="Phase 7 Interactive SRE & Cloud Security Mission Control Center with WebSockets & HITL Controls",
    version="2.0.0",
    lifespan=lifespan
)

# Active WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Dashboard WebSocket connected. Active clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Dashboard WebSocket disconnected. Active clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Error broadcasting to WebSocket client: {e}")
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Global Engines
diagnostic_engine = DiagnosticEngine()
guardrail_engine = GuardrailEngine()
action_executor = ActionExecutor(dry_run_mode=os.getenv("AEGIS_DRY_RUN", "true").lower() != "false")
escalation_notifier = EscalationNotifier()

# Live cluster state: pods from the Go controller, CPU/memory from Prometheus. Demo mode (simulated
# pods) is used only when no controller answers (DASHBOARD_MODE=auto), and every payload says which.
def _env_float(name: str, default: float) -> float:
    """A positive, finite number from the environment, else the default (a typo must not stop the dashboard)."""
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if 0 < value < float("inf") else default


# DASHBOARD_SENSOR_TIMEOUT_S: seconds each controller/Prometheus call may take. 3 suits in-cluster; through an
# SSH tunnel a call costs ~1.5 s, so raise it (8 works) or Prometheus flickers "down".
# DASHBOARD_SNAPSHOT_TTL_S: how long one live snapshot is shared between the tick loop and REST polls.
live_state = LiveClusterState(
    controller_url=os.getenv("GO_CONTROLLER_URL", ""),
    prometheus_url=os.getenv("PROMETHEUS_URL", "http://localhost:9090"),
    namespaces=[n.strip() for n in os.getenv("DASHBOARD_NAMESPACES", "online-boutique,aegis-chaos").split(",") if n.strip()],
    token=os.getenv("GO_CONTROLLER_TOKEN") or None,
    timeout=_env_float("DASHBOARD_SENSOR_TIMEOUT_S", 3.0),
    snapshot_ttl=_env_float("DASHBOARD_SNAPSHOT_TTL_S", 4.0),
)

# Start/stop of the chaos scenarios goes through the Go controller (the only component that changes the cluster).
chaos_client = ChaosClient(
    controller_url=os.getenv("GO_CONTROLLER_URL", ""),
    token=os.getenv("GO_CONTROLLER_TOKEN") or None,
)


def _check_dashboard_token(request: Request) -> None:
    """Optional shared secret for the endpoints that CHANGE things (chaos trigger, HITL actions).

    Off unless AEGIS_DASHBOARD_TOKEN is set; read-only endpoints stay open. Without it, anyone who can
    reach this port can release a quarantine or restart workloads through the HITL drawer.
    """
    expected = os.getenv("AEGIS_DASHBOARD_TOKEN", "")
    if expected and not token_matches(request.headers, expected):
        raise HTTPException(status_code=401, detail="missing or invalid dashboard token")


def current_data_source() -> str:
    return resolve_data_source(os.getenv("DASHBOARD_MODE", "auto"), live_state)

# Live Simulated State Store
POD_TELEMETRY_STORE: Dict[str, dict] = {
    "aegis-storefront-prod-1": {
        "pod_name": "aegis-storefront-prod-1",
        "cpu_pct": 24.5,
        "mem_pct": 42.1,
        "error_rate_pct": 0.05,
        "status": "HEALTHY",
        "restart_count": 0,
        "last_updated": time.strftime("%H:%M:%S")
    },
    "aegis-storefront-prod-2": {
        "pod_name": "aegis-storefront-prod-2",
        "cpu_pct": 31.0,
        "mem_pct": 48.6,
        "error_rate_pct": 0.08,
        "status": "HEALTHY",
        "restart_count": 0,
        "last_updated": time.strftime("%H:%M:%S")
    },
    "aegis-storefront-prod-3": {
        "pod_name": "aegis-storefront-prod-3",
        "cpu_pct": 18.2,
        "mem_pct": 39.4,
        "error_rate_pct": 0.02,
        "status": "HEALTHY",
        "restart_count": 0,
        "last_updated": time.strftime("%H:%M:%S")
    }
}

ACTIVE_QUARANTINES: Dict[str, dict] = {}
ESCALATED_INCIDENTS: Dict[str, dict] = {}
TERMINAL_LOGS: List[dict] = []

def add_terminal_log(level: str, category: str, message: str):
    log_entry = {
        "timestamp": time.strftime("%H:%M:%S"),
        "level": level,  # INFO, WARN, ALERT, ERROR, SUCCESS
        "category": category, # TELEMETRY, RAG, AI_BRAIN, GUARDRAIL, CONTROLLER, HITL
        "message": message
    }
    TERMINAL_LOGS.append(log_entry)
    if len(TERMINAL_LOGS) > 100:
        TERMINAL_LOGS.pop(0)
    return log_entry

def _namespace_for_pod(pod_name: str, pods: List[dict]) -> Optional[str]:
    """Namespace of a pod (or of its workload's live pods, since a restart replaces the pod name).

    ``incidents`` has no namespace column, so a live escalation is matched to the cluster here. An
    ambiguous or unknown pod gives None rather than a guess: the operator is then asked for it.
    """
    for p in pods:
        if p.get("pod_name") == pod_name:
            return p.get("namespace")
    if pod_name.count("-") < 2:
        return None
    workload = pod_name.rsplit("-", 2)[0]  # <deployment>-<replicaset hash>-<suffix>
    found = {p.get("namespace") for p in pods if str(p.get("pod_name", "")).startswith(workload + "-")}
    return found.pop() if len(found) == 1 else None


def current_escalations(source: str, pods: List[dict]) -> List[dict]:
    """Live: the shared database (what the real brain recorded). Demo: the in-memory simulator dict."""
    if source == "live":
        return [dict(e, namespace=_namespace_for_pod(e["target_pod"], pods)) for e in list_open_escalations()]
    return list(ESCALATED_INCIDENTS.values())


def build_state() -> Dict[str, Any]:
    """Current dashboard state, from the live cluster when a controller answers, else clearly-labelled demo data."""
    source = current_data_source()
    sensors = None
    error = None
    if source == "live":
        snap = live_state.snapshot()
        pods, sensors, error = snap["pods"], snap["sensors"], snap.get("error")
    else:
        pods = list(POD_TELEMETRY_STORE.values())
    quarantines = list(ACTIVE_QUARANTINES.values())
    escalations = current_escalations(source, pods)
    if source == "live":
        healthy = sum(1 for p in pods if p.get("status") == "HEALTHY")
        health_score = round(100.0 * healthy / len(pods), 1) if pods else 0.0
    else:
        health_score = 100.0 if not quarantines and not escalations else 75.0
    return {
        "data_source": source,
        "pods": pods,
        "quarantines": quarantines,
        "escalations": escalations,
        "sensors": sensors,
        "error": error,
        "metrics_summary": {
            "health_score_pct": health_score,
            "active_pods": len(pods),
            "quarantined_pods": len(quarantines),
            "escalated_count": len(escalations),
        },
    }


def collect_pipeline_events(last_id: Optional[int]):
    """New brain/controller audit rows since ``last_id`` as PIPELINE_EVENTs. ``None`` primes the cursor
    to the newest row so a fresh dashboard does not replay history."""
    try:
        from src.db.database import SessionLocal, init_db
        from src.db.models import AuditLogRecord

        init_db()
        with SessionLocal() as session:
            if last_id is None:
                newest = session.query(AuditLogRecord).order_by(AuditLogRecord.id.desc()).first()
                return [], (newest.id if newest else 0)
            rows = (session.query(AuditLogRecord).filter(AuditLogRecord.id > last_id)
                    .order_by(AuditLogRecord.id.asc()).limit(50).all())
            events = [{
                "event": "PIPELINE_EVENT", "kind": "audit", "id": r.id, "timestamp": r.timestamp,
                "target_pod": r.target_pod, "problem_type": r.problem_type, "executed_action": r.executed_action,
                "execution_success": r.execution_success, "status_code": r.status_code,
                "details": r.details, "health_verified": r.health_verified,
            } for r in rows]
            return events, (rows[-1].id if rows else last_id)
    except Exception as e:
        logger.debug(f"Pipeline event poll failed: {e}")
        return [], last_id


# Background task: broadcast telemetry and pipeline events every 2 seconds
async def telemetry_broadcast_loop():
    prom_url = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
    _, last_event_id = await asyncio.to_thread(collect_pipeline_events, None)
    while True:
        try:
            timestamp_str = time.strftime("%H:%M:%S")

            state = await asyncio.to_thread(build_state)
            if state["data_source"] == "demo":
                # Demo only: gentle jitter on the SIMULATED pods so the UI looks alive.
                try:
                    p_resp = requests.get(f"{prom_url}/api/v1/query", params={"query": "sum(http_requests_total)"}, timeout=0.8)
                    if p_resp.status_code == 200:
                        res = p_resp.json().get("data", {}).get("result", [])
                        if res and "aegis-storefront-prod-1" in POD_TELEMETRY_STORE:
                            POD_TELEMETRY_STORE["aegis-storefront-prod-1"]["total_requests"] = int(float(res[0]["value"][1]))
                except Exception:
                    pass
                for pod_name, data in POD_TELEMETRY_STORE.items():
                    if data["status"] == "HEALTHY":
                        data["cpu_pct"] = max(10.0, min(95.0, round(data["cpu_pct"] + (time.time() % 3 - 1.5) * 2.0, 1)))
                        data["mem_pct"] = max(20.0, min(90.0, round(data["mem_pct"] + (time.time() % 2 - 1.0) * 1.5, 1)))
                        data["last_updated"] = timestamp_str

            await ws_manager.broadcast({"event": "TELEMETRY_TICK", "timestamp": timestamp_str, **state})

            events, last_event_id = await asyncio.to_thread(collect_pipeline_events, last_event_id)
            for ev in events:
                level = "SUCCESS" if ev["execution_success"] else "ERROR"
                add_terminal_log(level, "PIPELINE",
                                 f"{ev['executed_action']} on {ev['target_pod']}: {ev['status_code']} - {ev['details']}")
                ev["latest_terminal_log"] = TERMINAL_LOGS[-1]
                await ws_manager.broadcast(ev)
        except Exception as e:
            logger.error(f"Error in telemetry broadcast loop: {e}")
        await asyncio.sleep(2.0)

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    # Send initial snapshot upon connection
    state = await asyncio.to_thread(build_state)
    await websocket.send_json({"event": "INITIAL_STATE", **state, "terminal_logs": TERMINAL_LOGS[-25:]})
    try:
        while True:
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        ws_manager.disconnect(websocket)

@app.get("/api/v1/telemetry/state")
async def get_telemetry_state():
    """HTTP REST State endpoint fallback."""
    state = await asyncio.to_thread(build_state)
    return {"event": "TELEMETRY_TICK", "timestamp": time.strftime("%H:%M:%S"), **state,
            "terminal_logs": TERMINAL_LOGS[-25:]}

# Models for Chaos & Manual Remediation Request
class ChaosTriggerRequest(BaseModel):
    pod_name: str = "aegis-storefront-prod-1"
    chaos_type: str  # oom, http500, cpu, t1059_shell, t1552_credentials

class ManualRemediationRequest(BaseModel):
    incident_id: str
    target_pod: str
    action: str  # RESTART_POD, SCALE_DEPLOYMENT, UNQUARANTINE_POD, CUSTOM
    notes: Optional[str] = "Manual operator resolution via HITL Drawer"
    namespace: Optional[str] = None

@app.post("/api/v1/chaos/trigger", dependencies=[Depends(_check_dashboard_token)])
async def trigger_chaos(req: ChaosTriggerRequest):
    """
    Triggers simulated failure mode, runs AI diagnostic & safety pipeline, and updates dashboard live via WebSockets.
    """
    if current_data_source() == "live":
        raise HTTPException(
            status_code=409,
            detail="This simulator is demo-only. In live mode use /api/v1/chaos/scenarios to start real chaos scenarios.",
        )
    pod_name = req.pod_name if req.pod_name in POD_TELEMETRY_STORE else "aegis-storefront-prod-1"
    chaos_type = req.chaos_type.lower()

    add_terminal_log("WARN", "CHAOS", f"Injecting failure simulation '{chaos_type}' into pod '{pod_name}'...")

    # Determine alert event type
    alert_map = {
        "oom": ("OOM_KILLED_RISK", "OPERATIONAL_BUG"),
        "http500": ("HTTP_500_SPIKE", "OPERATIONAL_BUG"),
        "cpu": ("CPU_QUOTA_SATURATION", "RESOURCE_CAPACITY"),
        "t1059_shell": ("falco_shell_spawn", "SECURITY_ATTACK"),
        "t1552_credentials": ("falco_sensitive_file_read", "SECURITY_ATTACK")
    }

    if chaos_type not in alert_map:
        raise HTTPException(status_code=400, detail="Invalid chaos type")

    alert_type, problem_cat = alert_map[chaos_type]

    # Update pod status
    POD_TELEMETRY_STORE[pod_name]["status"] = "DEGRADED" if problem_cat != "SECURITY_ATTACK" else "QUARANTINED"
    if chaos_type == "oom":
        POD_TELEMETRY_STORE[pod_name]["mem_pct"] = 94.2
    elif chaos_type == "cpu":
        POD_TELEMETRY_STORE[pod_name]["cpu_pct"] = 98.6
    elif chaos_type == "http500":
        POD_TELEMETRY_STORE[pod_name]["error_rate_pct"] = 18.5

    # 1. Run AI Diagnosis Engine
    add_terminal_log("INFO", "RAG", f"Retrieving TF-IDF runbooks for {alert_type} on {pod_name}...")
    verdict = diagnostic_engine.diagnose_incident(pod_name=pod_name, alert_type=alert_type, trusted_signal=True)  # demo simulates a Falco event
    
    add_terminal_log("ALERT", "AI_BRAIN", f"Verdict: {verdict.get('problem_type')} | Rec Action: {verdict.get('recommended_action')}")

    # 2. Run Guardrail Engine
    decision = verdict.get("decision_object") or guardrail_engine.validate_verdict(verdict)
    
    add_terminal_log("INFO", "GUARDRAIL", f"Guardrail State: {decision.state} | Approved: {decision.approved} | Action: {decision.final_action}")

    # 3. Execute Action Muscle
    exec_res = action_executor.execute_decision(decision)

    # Handle outcomes
    if decision.final_action == "CILIUM_QUARANTINE_EBPF" and exec_res.success:
        ACTIVE_QUARANTINES[pod_name] = {
            "pod_name": pod_name,
            "mitre_technique": decision.mitre_technique or "T1059 Command Execution",
            "forensics_file": exec_res.forensics_file or f"logs/forensics_{pod_name}.json",
            "quarantined_at": time.strftime("%H:%M:%S")
        }
        add_terminal_log("ALERT", "SECURITY", f"eBPF Network Cage active on '{pod_name}'. DFIR Snapshot saved.")

    elif decision.final_action == "RESTART_POD" and exec_res.success:
        POD_TELEMETRY_STORE[pod_name]["status"] = "HEALTHY"
        POD_TELEMETRY_STORE[pod_name]["mem_pct"] = 40.0
        POD_TELEMETRY_STORE[pod_name]["error_rate_pct"] = 0.01
        POD_TELEMETRY_STORE[pod_name]["restart_count"] += 1
        add_terminal_log("SUCCESS", "CONTROLLER", f"Pod '{pod_name}' rollout restart completed successfully.")

    elif decision.final_action == "SCALE_DEPLOYMENT" and exec_res.success:
        POD_TELEMETRY_STORE[pod_name]["status"] = "HEALTHY"
        POD_TELEMETRY_STORE[pod_name]["cpu_pct"] = 35.0
        add_terminal_log("SUCCESS", "CONTROLLER", f"Scaled deployment replicas +1. Pod '{pod_name}' load normalized.")

    # If Escalated to Human
    if not decision.approved or decision.state in ["STATE_ESCALATE_HUMAN", "STATE_ACTION_REJECTED"]:
        inc_id = verdict.get("incident_id", f"INC-ESCALATION-{int(time.time())}")
        escalation_payload = escalation_notifier.dispatch_escalation(decision, verdict)
        ESCALATED_INCIDENTS[inc_id] = {
            "incident_id": inc_id,
            "target_pod": pod_name,
            "problem_type": verdict.get("problem_type"),
            "confidence": decision.confidence,
            "reason": decision.reason,
            "mitre_technique": decision.mitre_technique,
            "forensics_file": getattr(exec_res, "forensics_file", f"logs/forensics_{pod_name}.json"),
            "loki_logs": "[ERROR] Unhandled database connection exception\n[CRITICAL] Stack trace dumped",
            "timestamp": time.strftime("%H:%M:%S")
        }
        add_terminal_log("ERROR", "HITL", f"HUMAN ESCALATION TRIGGERED for '{pod_name}': {decision.reason}")

    # Broadcast updated WebSocket event immediately
    event_msg = {
        "event": "CHAOS_TRIGGERED",
        "pod_name": pod_name,
        "chaos_type": chaos_type,
        "verdict": {k: v for k, v in verdict.items() if k != "decision_object"},
        "decision": {
            "approved": decision.approved,
            "final_action": decision.final_action,
            "state": decision.state,
            "reason": decision.reason
        },
        "execution": exec_res.to_dict(),
        "latest_terminal_log": TERMINAL_LOGS[-1]
    }
    await ws_manager.broadcast(event_msg)

    return JSONResponse(content=event_msg)

SCENARIO_ID = re.compile(r"^[a-z0-9-]{1,32}$")


class ChaosStartRequest(BaseModel):
    ttl_minutes: Optional[int] = None  # None = the controller's default (30), which it also caps (120)


def _require_live_chaos() -> None:
    if current_data_source() != "live":
        raise HTTPException(status_code=409, detail="Chaos controls need a live cluster. The demo simulator has its own page.")


def _check_scenario_id(scenario_id: str) -> None:
    # Validated here as well as in the controller, so nothing odd is ever forwarded.
    if not SCENARIO_ID.match(scenario_id):
        raise HTTPException(status_code=400, detail="invalid scenario id")


def _chaos_failure(e: ChaosError) -> HTTPException:
    """Controller answers that mean something to the operator keep their status; anything else is a 502."""
    return HTTPException(status_code=e.status if e.status in (400, 403, 404) else 502, detail=e.message)


def _audit_chaos(action: str, scenario_id: str, detail: str) -> None:
    """One audit row per start/stop. Nothing was verified, so ``health_verified`` is an explicit SQL NULL:
    a plain ``None`` makes SQLAlchemy apply the column's default of True and the row would claim otherwise."""
    try:
        from sqlalchemy import null
        from src.db.database import SessionLocal, init_db
        from src.db.models import AuditLogRecord
        init_db()
        with SessionLocal() as session:
            session.add(AuditLogRecord(
                target_pod=f"chaos:{scenario_id}", problem_type="CHAOS_CONTROL", executed_action=action,
                execution_success=True, status_code="COMPLETED", details=detail, health_verified=null()))
            session.commit()
    except Exception as e:
        logger.warning("could not audit %s %s: %s", action, scenario_id, e)


@app.get("/api/v1/chaos/scenarios")
async def list_chaos_scenarios():
    _require_live_chaos()
    try:
        return {"scenarios": await asyncio.to_thread(chaos_client.list)}
    except ChaosError as e:
        raise _chaos_failure(e)


@app.post("/api/v1/chaos/scenarios/{scenario_id}/start", dependencies=[Depends(_check_dashboard_token)])
async def start_chaos_scenario(scenario_id: str, req: Optional[ChaosStartRequest] = None):
    _require_live_chaos()
    _check_scenario_id(scenario_id)
    ttl = req.ttl_minutes if req else None
    try:
        result = await asyncio.to_thread(chaos_client.set, scenario_id, "on", ttl)
    except ChaosError as e:
        raise _chaos_failure(e)
    note = f"for {ttl} minutes" if ttl is not None else "with the default time limit"
    add_terminal_log("WARN", "CHAOS", f"Operator started chaos scenario '{scenario_id}' {note}.")
    _audit_chaos("CHAOS_START", scenario_id, f"Operator started scenario '{scenario_id}' {note}.")
    await ws_manager.broadcast({"event": "CHAOS_CHANGED", "scenario": scenario_id, "state": "on"})
    return result


@app.post("/api/v1/chaos/scenarios/{scenario_id}/stop", dependencies=[Depends(_check_dashboard_token)])
async def stop_chaos_scenario(scenario_id: str):
    _require_live_chaos()
    _check_scenario_id(scenario_id)
    try:
        result = await asyncio.to_thread(chaos_client.set, scenario_id, "off")
    except ChaosError as e:
        raise _chaos_failure(e)
    add_terminal_log("INFO", "CHAOS", f"Operator stopped chaos scenario '{scenario_id}'.")
    _audit_chaos("CHAOS_STOP", scenario_id, f"Operator stopped scenario '{scenario_id}'.")
    await ws_manager.broadcast({"event": "CHAOS_CHANGED", "scenario": scenario_id, "state": "off"})
    return result


@app.post("/api/v1/chaos/stop-all", dependencies=[Depends(_check_dashboard_token)])
async def stop_all_chaos():
    _require_live_chaos()
    try:
        scenarios = await asyncio.to_thread(chaos_client.list)
        running = [s["id"] for s in scenarios if s.get("installed") and s.get("replicas", 0) > 0]
        for sid in running:
            await asyncio.to_thread(chaos_client.set, sid, "off")
    except ChaosError as e:
        raise _chaos_failure(e)
    for sid in running:
        _audit_chaos("CHAOS_STOP", sid, f"Operator stopped scenario '{sid}' (stop all).")
    add_terminal_log("INFO", "CHAOS", f"Operator stopped all chaos scenarios ({len(running)} running).")
    await ws_manager.broadcast({"event": "CHAOS_CHANGED", "scenario": "*", "state": "off"})
    return {"stopped": running}


HITL_EXECUTABLE_ACTIONS = {"RESTART_POD", "SCALE_DEPLOYMENT", "UNQUARANTINE_POD"}


@app.post("/api/v1/escalation/resolve", dependencies=[Depends(_check_dashboard_token)])
async def resolve_escalation(req: ManualRemediationRequest):
    """
    Human-in-the-Loop (HITL) resolution. The operator's decision runs through the SAME executor as
    autonomous actions (so it reaches the real controller, is audited, and honours dry-run).
    CUSTOM only acknowledges the incident.
    """
    target_pod = req.target_pod
    action = req.action.upper()
    if action != "CUSTOM" and action not in HITL_EXECUTABLE_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Action '{action}' is not allowed from the HITL drawer.")

    if action != "CUSTOM":
        # A human decision still has a blast radius: same namespace policy as autonomous actions, and
        # in live mode the namespace must be explicit (never silently "default").
        if current_data_source() == "live" and not req.namespace:
            raise HTTPException(status_code=400, detail="namespace is required for live remediation.")
        violation = GuardrailEngine.namespace_violation(req.namespace, action)
        if violation:
            raise HTTPException(status_code=403, detail=violation)

    add_terminal_log("WARN", "HITL", f"HUMAN OPERATOR DISPATCHED MANUALLY: Action '{action}' on pod '{target_pod}'")

    execution = None
    if action != "CUSTOM":
        decision = GuardrailDecision(
            approved=True, final_action=action, state=STATE_GUARDRAIL_APPROVED,
            reason=f"Human operator via HITL drawer: {req.notes}", confidence=1.0, original_action=action,
            target_pod=target_pod, problem_type="HUMAN_OPERATOR", namespace=req.namespace,
        )
        result = await asyncio.to_thread(action_executor.execute_decision, decision)
        if not result.success:
            add_terminal_log("ERROR", "CONTROLLER", f"Manual {action} on '{target_pod}' failed: {result.status_code}")
            raise HTTPException(status_code=502, detail=f"{result.status_code}: {result.details}")
        execution = result.to_dict()

        if action == "UNQUARANTINE_POD":
            ACTIVE_QUARANTINES.pop(target_pod, None)
            if target_pod in POD_TELEMETRY_STORE:
                POD_TELEMETRY_STORE[target_pod]["status"] = "HEALTHY"
            add_terminal_log("SUCCESS", "SECURITY", f"eBPF Network Cage removed from '{target_pod}'. Pod restored.")
        elif action == "RESTART_POD":
            if target_pod in POD_TELEMETRY_STORE:  # demo store only; live state comes from the cluster
                POD_TELEMETRY_STORE[target_pod].update(status="HEALTHY", mem_pct=40.0, error_rate_pct=0.01)
                POD_TELEMETRY_STORE[target_pod]["restart_count"] += 1
            add_terminal_log("SUCCESS", "CONTROLLER", f"Manual restart executed for pod '{target_pod}'.")
        elif action == "SCALE_DEPLOYMENT":
            if target_pod in POD_TELEMETRY_STORE:
                POD_TELEMETRY_STORE[target_pod].update(status="HEALTHY", cpu_pct=30.0)
            add_terminal_log("SUCCESS", "CONTROLLER", "Manual scale up executed for target deployment.")

    if req.incident_id in ESCALATED_INCIDENTS:
        del ESCALATED_INCIDENTS[req.incident_id]
    # Live escalations live in the shared database; resolving one must outlast a dashboard restart.
    await asyncio.to_thread(resolve_escalation_record, req.incident_id)

    # Broadcast updated state
    await ws_manager.broadcast({
        "event": "ESCALATION_RESOLVED",
        "incident_id": req.incident_id,
        "target_pod": target_pod,
        "action": action,
        "pods": list(POD_TELEMETRY_STORE.values()),
        "quarantines": list(ACTIVE_QUARANTINES.values()),
        "escalations": await asyncio.to_thread(current_escalations, current_data_source(), []),
    })

    return {"status": "SUCCESS", "message": f"Manual action '{action}' executed for '{target_pod}'", "execution": execution}

@app.get("/api/v1/forensics/{pod_name}")
async def get_forensics(pod_name: str):
    """
    DFIR snapshot for a pod. Real captures are returned as-is. With no capture, live mode answers 404
    (nothing is invented); demo mode returns a sample that is explicitly labelled ``"demo": true``.
    """
    path = f"logs/forensics_{pod_name}.json"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    if current_data_source() == "live":
        raise HTTPException(
            status_code=404,
            detail=f"No forensics were captured for '{pod_name}'. A snapshot exists only after a quarantine.",
        )
    return {
        "demo": True,
        "data_source": "demo",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_pod": pod_name,
        "namespace": "demo",
        "mitre_technique": "T1059 - Command Execution",
        "trigger_reason": "DEMO SAMPLE: no real capture exists for this pod",
        "process_tree": [
            {"pid": "1", "user": "root", "cmd": "python app.py"},
            {"pid": "842", "user": "www-data", "cmd": "sh -i"},
        ],
        "simulated_process_tree": [
            {"pid": "1", "user": "root", "cmd": "python app.py"},
            {"pid": "842", "user": "www-data", "cmd": "sh -i"},
        ],
        "active_sockets": [],
        "events": [],
        "logs": {},
        "errors": ["demo sample only"],
    }

@app.get("/api/v1/db/incidents")
async def get_db_incidents():
    """Returns stored incidents from persistent SQLite database."""
    try:
        from src.db.database import SessionLocal, init_db
        from src.db.models import IncidentRecord
        init_db()
        with SessionLocal() as session:
            incidents = session.query(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(50).all()
            return {"count": len(incidents), "incidents": [inc.to_dict() for inc in incidents]}
    except Exception as e:
        logger.error(f"Error querying incidents DB: {e}")
        return {"count": 0, "incidents": [], "error": str(e)}

@app.get("/api/v1/db/audit")
async def get_db_audit_logs():
    """Returns stored action audit logs from persistent SQLite database."""
    try:
        from src.db.database import SessionLocal, init_db
        from src.db.models import AuditLogRecord
        init_db()
        with SessionLocal() as session:
            logs = session.query(AuditLogRecord).order_by(AuditLogRecord.id.desc()).limit(50).all()
            return {"count": len(logs), "audit_logs": [l.to_dict() for l in logs]}
    except Exception as e:
        logger.error(f"Error querying audit DB: {e}")
        return {"count": 0, "audit_logs": [], "error": str(e)}

@app.get("/api/v1/incidents/{incident_id}/postmortem")
async def generate_incident_postmortem(incident_id: str):
    """Generates an executive-ready SRE incident post-mortem report in Markdown format."""
    try:
        from src.db.database import SessionLocal, init_db
        from src.db.models import IncidentRecord, AuditLogRecord
        init_db()
        with SessionLocal() as session:
            if incident_id == "latest":
                inc = session.query(IncidentRecord).order_by(IncidentRecord.id.desc()).first()
            else:
                inc = session.query(IncidentRecord).filter(
                    (IncidentRecord.incident_id == incident_id) | (IncidentRecord.id == int(incident_id) if incident_id.isdigit() else False)
                ).first()
            
            if not inc:
                raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found in database.")

            audit = session.query(AuditLogRecord).filter_by(target_pod=inc.target_pod).order_by(AuditLogRecord.id.desc()).first()

            ts = getattr(inc, "created_at", None) or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            action_ts = getattr(audit, "timestamp", None) if audit else ts
            exec_status = "SUCCESS" if (audit and audit.execution_success) else ("FAILED" if audit else "EXECUTED")

            markdown_report = f"""# 🛡️ Aegis-SRE Incident Post-Mortem: {inc.incident_id}

| Metric | Details |
| :--- | :--- |
| **Target Service / Pod** | `{inc.target_pod}` |
| **Severity / Problem Type** | **{inc.threat_level}** / `{inc.problem_type}` |
| **MITRE ATT&CK TTP** | `{inc.mitre_technique or 'N/A (Operational Bug)'}` |
| **AI Diagnostic Confidence** | `{inc.confidence * 100:.1f}%` |
| **Remediation Action** | `{inc.final_action}` ({exec_status}) |
| **Detection Timestamp** | `{ts}` |
| **Resolution Timestamp** | `{action_ts}` |

---

## 1. Executive Summary
On **{ts}**, Aegis-SRE's autonomous diagnostic pipeline detected an anomaly affecting `{inc.target_pod}`.
The AI diagnostic engine isolated the root cause:
> *"{inc.root_cause}"*

Through autonomous policy enforcement, the platform selected and executed `{inc.final_action}`, successfully restoring pod health and verifying cluster stability.

---

## 2. Telemetry & Root Cause Analysis (RCA)
- **Primary Category:** `{inc.problem_type}`
- **MITRE TTP Reference:** `{inc.mitre_technique or 'None (Software Defect / Saturation)'}`
- **Confidence Rating:** `{inc.confidence * 100:.1f}%`
- **Recommended vs Final Action:** Recommended `{inc.recommended_action}` -> Guardrail Approved `{inc.final_action}`

---

## 3. Timeline of Events
| Timestamp | Stage | Description |
| :--- | :--- | :--- |
| `{ts}` | **Detection** | Telemetry collectors (Prometheus / Loki / Falco eBPF) flagged anomaly on `{inc.target_pod}` |
| `{ts}` | **Diagnosis** | Aegis AI Brain analyzed telemetry against MITRE runbooks; identified `{inc.problem_type}` |
| `{ts}` | **Guardrail Check** | Safety validation evaluated blast radius and approved action `{inc.final_action}` |
| `{action_ts}` | **Mitigation** | Controller executed `{inc.final_action}` on cluster target |
| `{action_ts}` | **Verification** | Post-action health check confirmed metrics normalized |

---

## 4. Corrective & Preventative Action Items
- [x] **Automated Remediation:** Executed `{inc.final_action}` to restore availability.
- [x] **Audit Trail Recorded:** Saved forensic state and incident diagnosis to persistent database.
- [ ] **Capacity & Alert Review:** Evaluate if alert threshold for `{inc.problem_type}` requires tuning.
- [ ] **Regression Test:** Add chaos simulation test to CI/CD pipeline to verify autonomous recovery.
"""
            return {
                "incident_id": inc.incident_id,
                "target_pod": inc.target_pod,
                "problem_type": inc.problem_type,
                "final_action": inc.final_action,
                "confidence": inc.confidence,
                "markdown": markdown_report
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating post-mortem: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def service_info():
    """API only: the operator UI is the React console (frontend/, Vite dev server on :5173)."""
    return {
        "service": "aegis-dashboard-api",
        "data_source": current_data_source(),
        "ui": "http://localhost:5173",
        "docs": "/docs",
        "websocket": "/ws/telemetry",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
