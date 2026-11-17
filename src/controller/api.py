import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

from src.guardrails.action_schema import GuardrailDecision, is_valid_k8s_name, validate_controller_decision
from src.guardrails.validator import GuardrailEngine
from src.controller.executor import ActionExecutor, ActionExecutionResult

logger = logging.getLogger("aegis-controller-api")

router = APIRouter(prefix="/api/v1/controller", tags=["Action Muscle Controller"])
executor = ActionExecutor(dry_run_mode=True)


class DecisionExecutionRequest(BaseModel):
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


@router.get("/health")
async def controller_health():
    return {
        "status": "healthy",
        "service": "aegis-action-muscle-controller",
        "dry_run_mode": executor.dry_run_mode,
        "supported_actions": [
            "RESTART_POD",
            "SCALE_DEPLOYMENT",
            "CILIUM_QUARANTINE_EBPF",
            "UNQUARANTINE_POD",
            "ESCALATE"
        ]
    }


@router.post("/execute", response_model=Dict[str, Any])
async def execute_guardrail_decision(req: DecisionExecutionRequest):
    """
    Receives validated GuardrailDecision payload and dispatches cluster action execution.
    Schema validation runs before any controller mutation.
    """
    parsed, err = validate_controller_decision(req.model_dump())
    if err or parsed is None:
        logger.warning("CONTROLLER REJECT: schema validation failed — %s", err)
        raise HTTPException(status_code=400, detail=err or "Invalid decision schema")

    if not is_valid_k8s_name(parsed.target_pod) or (
        parsed.namespace is not None and not is_valid_k8s_name(parsed.namespace)
    ):
        raise HTTPException(status_code=400, detail="Invalid pod or namespace name.")
    if parsed.final_action != "ESCALATE":
        violation = GuardrailEngine.namespace_violation(parsed.namespace, parsed.final_action)
        if violation:
            raise HTTPException(status_code=403, detail=violation)

    try:
        decision = GuardrailDecision(
            approved=parsed.approved,
            final_action=parsed.final_action,
            state=parsed.state,
            reason=parsed.reason,
            confidence=parsed.confidence,
            original_action=parsed.original_action,
            target_pod=parsed.target_pod,
            problem_type=parsed.problem_type,
            mitre_technique=parsed.mitre_technique,
            rate_limit_exceeded=parsed.rate_limit_exceeded,
            namespace=parsed.namespace,
        )

        result: ActionExecutionResult = executor.execute_decision(decision)
        return {
            "execution_status": "SUCCESS" if result.success else "FAILED",
            "result": result.to_dict()
        }
    except Exception as e:
        logger.error(f"Error executing controller action: {e}")
        raise HTTPException(status_code=500, detail=str(e))
