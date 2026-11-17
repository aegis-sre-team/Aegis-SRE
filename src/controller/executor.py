import time
import os
from datetime import datetime, timezone
import json
import logging
import subprocess
from typing import Dict, Any, Optional

from src.guardrails.action_schema import (
    GuardrailDecision,
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN
)
from src.controller.cilium_policy import CiliumPolicyGenerator, QUARANTINE_LABEL, quarantine_label_value

logger = logging.getLogger("aegis-action-executor")


class ActionExecutionResult:
    """Represents the execution outcome of a remediation action."""
    def __init__(self,
                 success: bool,
                 action: str,
                 target_pod: str,
                 details: str,
                 status_code: str = "COMPLETED",
                 policy_applied: Optional[Dict[str, Any]] = None,
                 forensics_file: Optional[str] = None,
                 health_verified: bool = True,
                 workload: Optional[str] = None):
        self.success = success
        self.action = action
        self.target_pod = target_pod
        self.details = details
        self.status_code = status_code
        self.policy_applied = policy_applied
        self.forensics_file = forensics_file
        self.health_verified = health_verified
        self.workload = workload
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @property
    def dry_run(self) -> bool:
        return "DRY_RUN" in (self.status_code or "").upper()

    def effective_health_verified(self):
        """What the audit trail and API may claim: a dry run verified nothing, so None (not True)."""
        return None if self.dry_run else self.health_verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "success": self.success,
            "action": self.action,
            "target_pod": self.target_pod,
            "details": self.details,
            "status_code": self.status_code,
            "policy_applied": self.policy_applied,
            "forensics_file": self.forensics_file,
            "health_verified": self.effective_health_verified(),
            "dry_run": self.dry_run,
            "workload": self.workload
        }


class ActionExecutor:
    """
    Action Muscle Executor Engine (Phase 5).
    Translates Guardrail-validated decisions into live Kubernetes API / eBPF operations,
    captures automated security DFIR snapshots, and verifies post-remediation health.
    """

    def __init__(self,
                 namespace: str = "default",
                 audit_log_path: str = "logs/controller_audit.jsonl",
                 dry_run_mode: bool = True,
                 forensics_dir: str = "logs"):
        self.namespace = namespace
        self.audit_log_path = audit_log_path
        self.dry_run_mode = dry_run_mode
        self.forensics_dir = forensics_dir
        self._sleep = time.sleep  # injectable so tests do not really wait
        self.policy_generator = CiliumPolicyGenerator()

    def _owner_of(self, target_pod: str, namespace: str):
        """(kind, name) of the pod's first owner via kubectl, or None (dry-run never calls kubectl)."""
        if self.dry_run_mode:
            return None
        try:
            res = subprocess.run(
                ["kubectl", "get", "pod", target_pod, "-n", namespace, "-o",
                 "jsonpath={.metadata.ownerReferences[0].kind} {.metadata.ownerReferences[0].name}"],
                capture_output=True, text=True, timeout=5
            )
            if res.returncode == 0 and res.stdout.strip():
                kind, _, name = res.stdout.strip().partition(" ")
                if kind and name:
                    return kind, name
        except Exception as e:
            logger.debug(f"Could not resolve the owner via kubectl ownerReferences: {e}")
        return None

    def _resolve_workload_ref(self, target_pod: str, namespace: str = "default") -> str:
        """`kind/name` for kubectl. ReplicaSet owners map to their Deployment; StatefulSet and DaemonSet
        pods keep their own kind and name (stripping a suffix is only right for ReplicaSets)."""
        owner = self._owner_of(target_pod, namespace)
        if owner:
            kind, name = owner
            if kind == "ReplicaSet":
                return f"deployment/{name.rsplit('-', 1)[0] if '-' in name else name}"
            if kind in ("StatefulSet", "DaemonSet"):
                return f"{kind.lower()}/{name}"
        return f"deployment/{self._heuristic_deployment_name(target_pod)}"

    def _resolve_deployment_name(self, target_pod: str, namespace: str = "default") -> str:
        """Name part of the resolved workload (kept for callers that only need the name)."""
        return self._resolve_workload_ref(target_pod, namespace).split("/", 1)[1]

    @staticmethod
    def _heuristic_deployment_name(target_pod: str) -> str:
        # Dynamic naming heuristic:
        # e.g., 'aegis-storefront-prod-1' -> 'aegis-storefront-prod'
        # e.g., 'checkout-service-74bb65757d-4f27q' -> 'checkout-service'
        parts = target_pod.split("-")
        if len(parts) >= 3:
            if len(parts[-2]) in [8, 9, 10]:
                return "-".join(parts[:-2])
            return "-".join(parts[:-1])
        elif len(parts) == 2:
            return parts[0]
        return target_pod

    def restart_pod(self, target_pod: str, namespace: str = "default", reason: str = "") -> ActionExecutionResult:
        """
        Executes pod restart via Kubernetes API / rollout restart and performs active health verification.
        """
        logger.info(f"CONTROLLER EXECUTE [RESTART_POD]: Initiating pod restart for '{target_pod}' in namespace '{namespace}'.")
        
        workload_ref = self._resolve_workload_ref(target_pod, namespace)
        deployment_name = workload_ref.split("/", 1)[1]

        if self.dry_run_mode:
            health_verified = self.verify_remediation_health(target_pod, "RESTART_POD", namespace, deployment_name)
            details = (
                f"[DRY_RUN SUCCESS] Issued rollout restart command for deployment '{deployment_name}' "
                f"to replace target pod '{target_pod}'. Reason: {reason}. Health verification: not performed (dry run)."
            )
            return ActionExecutionResult(
                success=True,
                action="RESTART_POD",
                target_pod=target_pod,
                details=details,
                status_code="COMPLETED_DRY_RUN",
                health_verified=health_verified
            )

        try:
            cmd = ["kubectl", "rollout", "restart", workload_ref, "-n", namespace]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                health_verified = self.verify_remediation_health(target_pod, "RESTART_POD", namespace, deployment_name)
                details = f"Successfully restarted deployment '{deployment_name}' (pod: '{target_pod}'). Output: {res.stdout.strip()}"
                return ActionExecutionResult(
                    success=True,
                    action="RESTART_POD",
                    target_pod=target_pod,
                    details=details,
                    status_code="COMPLETED_LIVE",
                    health_verified=health_verified
                )
            else:
                details = f"Kubectl restart returned error: {res.stderr.strip()}"
                return ActionExecutionResult(
                    success=False,
                    action="RESTART_POD",
                    target_pod=target_pod,
                    details=details,
                    status_code="FAILED_KUBECTL_ERR"
                )
        except Exception as e:
            logger.error(f"Error during pod restart: {e}")
            return ActionExecutionResult(
                success=False,
                action="RESTART_POD",
                target_pod=target_pod,
                details=f"Execution exception: {str(e)}",
                status_code="FAILED_EXCEPTION"
            )

    def scale_deployment(self, target_pod: str, replicas: Optional[int] = None,
                         namespace: str = "default") -> ActionExecutionResult:
        """
        Scale a workload UP. Same semantics as the Go controller: +1 replica, capped at MAX_REPLICAS
        (default 4), never down. An explicit `replicas` is still clamped to [1, cap].
        """
        workload_ref = self._resolve_workload_ref(target_pod, namespace)
        deployment_name = workload_ref.split("/", 1)[1]
        cap = max(1, int(os.getenv("MAX_REPLICAS", "4")))
        logger.info(f"CONTROLLER EXECUTE [SCALE_DEPLOYMENT]: Scaling '{deployment_name}' up (cap {cap}).")

        if self.dry_run_mode:
            health_verified = self.verify_remediation_health(target_pod, "SCALE_DEPLOYMENT", namespace, deployment_name)
            details = (f"[DRY_RUN SUCCESS] Would scale deployment '{deployment_name}' up by one replica "
                       f"(capped at {cap}). Health verification: not performed (dry run).")
            return ActionExecutionResult(
                success=True,
                action="SCALE_DEPLOYMENT",
                target_pod=target_pod,
                details=details,
                status_code="COMPLETED_DRY_RUN",
                health_verified=health_verified
            )

        try:
            target = replicas
            if target is None:
                cur = subprocess.run(["kubectl", "get", workload_ref, "-n", namespace, "-o", "jsonpath={.spec.replicas}"],
                                     capture_output=True, text=True, timeout=10)
                try:
                    current = int(cur.stdout.strip()) if cur.returncode == 0 and cur.stdout.strip() else 1
                except ValueError:
                    current = 1
                target = current + 1
            target = max(1, min(target, cap))
            cmd = ["kubectl", "scale", workload_ref, f"--replicas={target}", "-n", namespace]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                health_verified = self.verify_remediation_health(target_pod, "SCALE_DEPLOYMENT", namespace, deployment_name)
                return ActionExecutionResult(
                    success=True,
                    action="SCALE_DEPLOYMENT",
                    target_pod=target_pod,
                    details=f"Successfully scaled deployment '{deployment_name}' to {target} replicas.",
                    status_code="COMPLETED_LIVE",
                    health_verified=health_verified
                )
            else:
                return ActionExecutionResult(
                    success=False,
                    action="SCALE_DEPLOYMENT",
                    target_pod=target_pod,
                    details=f"Kubectl scale error: {res.stderr.strip()}",
                    status_code="FAILED_KUBECTL_ERR"
                )
        except Exception as e:
            return ActionExecutionResult(
                success=False,
                action="SCALE_DEPLOYMENT",
                target_pod=target_pod,
                details=f"Scale exception: {str(e)}",
                status_code="FAILED_EXCEPTION"
            )

    def quarantine_pod_ebpf(self,
                           target_pod: str,
                           namespace: str = "default",
                           mitre_technique: Optional[str] = None,
                           reason: Optional[str] = None) -> ActionExecutionResult:
        """
        Executes eBPF zero-trust quarantine via CiliumNetworkPolicy generation
        and automatically captures a Digital Forensics & Incident Response (DFIR) snapshot.
        """
        logger.info(f"CONTROLLER EXECUTE [CILIUM_QUARANTINE_EBPF]: Applying kernel-level eBPF quarantine to pod '{target_pod}'.")
        
        # 1. Capture automated DFIR forensics snapshot BEFORE network cut
        forensics_file = self._capture_dfir_forensics_snapshot(target_pod, mitre_technique, reason, namespace)

        # 2. Construct Cilium policy
        app_label = target_pod.split("-")[0] if "-" in target_pod else target_pod
        cilium_policy = self.policy_generator.generate_cilium_quarantine_policy(
            pod_name=target_pod,
            namespace=namespace,
            app_label=app_label,
            mitre_technique=mitre_technique,
            reason=reason
        )

        policy_yaml = self.policy_generator.to_yaml(cilium_policy)

        if self.dry_run_mode:
            self._record_quarantine_db(target_pod, namespace, mitre_technique, reason, forensics_file, policy_yaml, active=True)
            details = (
                f"[DRY_RUN SUCCESS] Generated zero-trust CiliumNetworkPolicy 'aegis-quarantine-{target_pod}' "
                f"enforcing eBPF drop-all ingress/egress. MITRE TTP: {mitre_technique or 'N/A'}. "
                f"Automated DFIR Forensics captured: '{forensics_file}'"
            )
            return ActionExecutionResult(
                success=True,
                action="CILIUM_QUARANTINE_EBPF",
                target_pod=target_pod,
                details=details,
                status_code="COMPLETED_DRY_RUN",
                policy_applied=cilium_policy,
                forensics_file=forensics_file,
                health_verified=True
            )

        try:
            # The policy selects pods by the quarantine label, so label the pod first.
            label = f"{QUARANTINE_LABEL}={quarantine_label_value(target_pod)}"
            lab = subprocess.run(
                ["kubectl", "label", "pod", target_pod, label, "--overwrite", "-n", namespace],
                capture_output=True, text=True, timeout=10,
            )
            if lab.returncode != 0:
                return ActionExecutionResult(
                    success=False,
                    action="CILIUM_QUARANTINE_EBPF",
                    target_pod=target_pod,
                    details=f"Failed to label pod for quarantine: {lab.stderr.strip()}",
                    status_code="FAILED_KUBECTL_ERR",
                    policy_applied=cilium_policy,
                    forensics_file=forensics_file,
                )
            # Apply policy via kubectl stdin
            proc = subprocess.Popen(
                ["kubectl", "apply", "-f", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=policy_yaml, timeout=10)

            if proc.returncode == 0:
                self._record_quarantine_db(target_pod, namespace, mitre_technique, reason, forensics_file, policy_yaml, active=True)
                details = f"CiliumNetworkPolicy applied successfully: {stdout.strip()}. Forensics saved to {forensics_file}."
                return ActionExecutionResult(
                    success=True,
                    action="CILIUM_QUARANTINE_EBPF",
                    target_pod=target_pod,
                    details=details,
                    status_code="COMPLETED_LIVE",
                    policy_applied=cilium_policy,
                    forensics_file=forensics_file,
                    health_verified=True
                )
            else:
                details = f"Failed to apply CiliumNetworkPolicy: {stderr.strip()}"
                return ActionExecutionResult(
                    success=False,
                    action="CILIUM_QUARANTINE_EBPF",
                    target_pod=target_pod,
                    details=details,
                    status_code="FAILED_KUBECTL_ERR",
                    policy_applied=cilium_policy,
                    forensics_file=forensics_file
                )
        except Exception as e:
            return ActionExecutionResult(
                success=False,
                action="CILIUM_QUARANTINE_EBPF",
                target_pod=target_pod,
                details=f"Quarantine exception: {str(e)}",
                status_code="FAILED_EXCEPTION",
                policy_applied=cilium_policy,
                forensics_file=forensics_file
            )

    def _record_quarantine_db(self, target_pod: str, namespace: str = "default", mitre_technique: str = None, reason: str = None, forensics_file: str = None, policy_yaml: str = None, active: bool = True):
        """Persist quarantine state. Rows are keyed "<namespace>/<pod>" inside the existing unique
        `target_pod` column (a pod name alone is ambiguous across namespaces, and the live table's
        unique constraint cannot be altered offline). Dry runs isolate nothing, so they record nothing;
        otherwise the dashboard would restore them at startup as real quarantines."""
        if self.dry_run_mode:
            return
        key = f"{namespace}/{target_pod}"
        try:
            from src.db.database import SessionLocal, init_db
            from src.db.models import QuarantineRecord
            init_db()
            with SessionLocal() as session:
                rec = session.query(QuarantineRecord).filter_by(target_pod=key).first()
                if rec:
                    rec.active = active
                    if active:
                        rec.mitre_technique = mitre_technique
                        rec.trigger_reason = reason
                        rec.forensics_file = forensics_file
                        rec.policy_yaml = policy_yaml
                elif active:
                    rec = QuarantineRecord(
                        target_pod=key,
                        namespace=namespace,
                        mitre_technique=mitre_technique,
                        trigger_reason=reason,
                        forensics_file=forensics_file,
                        policy_yaml=policy_yaml,
                        active=True
                    )
                    session.add(rec)
                session.commit()
        except Exception as e:
            logger.debug(f"SQLite quarantine recording fallback: {e}")

    def unquarantine_pod_ebpf(self, target_pod: str, namespace: str = "default") -> ActionExecutionResult:
        """
        Executes action reversibility: removes CiliumNetworkPolicy and restores pod traffic flow.
        """
        logger.info(f"CONTROLLER EXECUTE [UNQUARANTINE_POD]: Removing eBPF quarantine policy for pod '{target_pod}'.")
        policy_spec = self.policy_generator.generate_unquarantine_spec(target_pod, namespace)

        if self.dry_run_mode:
            details = f"[DRY_RUN SUCCESS] Removed CiliumNetworkPolicy 'aegis-quarantine-{target_pod}'. Normal pod network traffic restored."
            return ActionExecutionResult(
                success=True,
                action="UNQUARANTINE_POD",
                target_pod=target_pod,
                details=details,
                status_code="COMPLETED_DRY_RUN",
                policy_applied=policy_spec,
                health_verified=True
            )

        try:
            policy_name = f"aegis-quarantine-{target_pod}"
            cmd = ["kubectl", "delete", "ciliumnetworkpolicy", policy_name, "-n", namespace, "--ignore-not-found"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            subprocess.run(  # best effort: drop the selector label too
                ["kubectl", "label", "pod", target_pod, f"{QUARANTINE_LABEL}-", "-n", namespace],
                capture_output=True, text=True, timeout=10,
            )
            if res.returncode == 0:
                self._record_quarantine_db(target_pod, namespace=namespace, active=False)  # only once the cage is gone
                return ActionExecutionResult(
                    success=True,
                    action="UNQUARANTINE_POD",
                    target_pod=target_pod,
                    details=f"Successfully deleted CiliumNetworkPolicy '{policy_name}'. Pod traffic restored.",
                    status_code="COMPLETED_LIVE",
                    policy_applied=policy_spec,
                    health_verified=True
                )
            else:
                return ActionExecutionResult(
                    success=False,
                    action="UNQUARANTINE_POD",
                    target_pod=target_pod,
                    details=f"Kubectl delete policy error: {res.stderr.strip()}",
                    status_code="FAILED_KUBECTL_ERR",
                    policy_applied=policy_spec
                )
        except Exception as e:
            return ActionExecutionResult(
                success=False,
                action="UNQUARANTINE_POD",
                target_pod=target_pod,
                details=f"Unquarantine exception: {str(e)}",
                status_code="FAILED_EXCEPTION",
                policy_applied=policy_spec
            )

    def _dispatch_to_go_controller(self, decision: GuardrailDecision, namespace: str) -> Optional[Dict[str, Any]]:
        """
        POST the approved decision to the Go controller.

        Returns {"http_status": int, "body": dict} for ANY HTTP answer (so a refusal is not mistaken
        for an outage), or None when the controller cannot be reached at all.
        """
        import requests
        go_url = os.getenv("GO_CONTROLLER_URL", "http://localhost:8080/api/v1/reconcile")
        token = os.getenv("GO_CONTROLLER_TOKEN", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        payload = {
            "approved": decision.approved,
            "final_action": decision.final_action,
            "target_pod": decision.target_pod,
            "namespace": namespace,
            "problem_type": decision.problem_type,
            "mitre_technique": decision.mitre_technique or "",
            "reason": decision.reason or ""
        }
        try:
            resp = requests.post(go_url, json=payload, headers=headers, timeout=(3, 30))
        except Exception as e:
            logger.warning(f"Go controller unreachable at {go_url}: {e}")
            return None
        try:
            body = resp.json()
        except Exception:
            body = {}
        return {"http_status": resp.status_code, "body": body if isinstance(body, dict) else {}}

    @staticmethod
    def _kubectl_fallback_allowed() -> bool:
        return os.getenv("AEGIS_ALLOW_KUBECTL_FALLBACK", "false").lower() == "true"

    @staticmethod
    def _parse_process_list(text: Optional[str]) -> list:
        """Parse `ps` output into [{pid,user,cmd}] using the header row to locate columns."""
        if not text:
            return []
        lines = [ln for ln in text.strip().splitlines() if ln.strip()]
        if len(lines) < 2:
            return []
        header = [h.lower() for h in lines[0].split()]
        if "pid" not in header:
            return []
        out = []
        for ln in lines[1:]:
            parts = ln.split(None, len(header) - 1)
            if len(parts) < len(header):
                continue
            row = dict(zip(header, parts))
            out.append({
                "pid": row.get("pid"),
                "user": row.get("user"),
                "cmd": row.get("command") or row.get("cmd") or parts[-1],
            })
        return out

    def _forensics_target(self, pod: str):
        """(path_to_write, existing_real_snapshot_or_None).

        A REAL (cluster) snapshot is the pre-isolation evidence and is never overwritten: a later
        capture goes to a timestamped file next to it. Dry-run/empty files may be replaced freely.
        """
        base = os.path.join(self.forensics_dir, f"forensics_{pod}.json")
        if os.path.exists(base):
            try:
                with open(base, "r", encoding="utf-8") as f:
                    real = json.load(f).get("data_source") == "cluster"
            except Exception:
                real = False
            if real:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                return os.path.join(self.forensics_dir, f"forensics_{pod}_{stamp}.json"), base
        return base, None

    def _persist_controller_forensics(self, decision: GuardrailDecision, namespace: str,
                                      forensics: Optional[Dict[str, Any]]) -> str:
        """Write the controller's REAL snapshot to disk; absent evidence is reported as absent."""
        os.makedirs(self.forensics_dir, exist_ok=True)
        forensics = forensics if isinstance(forensics, dict) else None
        path, existing = self._forensics_target(decision.target_pod)
        if forensics is None and existing:
            return existing  # e.g. "already quarantined": keep the original evidence untouched
        logs = (forensics or {}).get("logs") or {}
        process_tree = self._parse_process_list((forensics or {}).get("process_list"))
        errors = list((forensics or {}).get("errors") or [])
        if forensics is None:
            errors.append("controller returned no forensics snapshot")
        data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_pod": decision.target_pod,
            "namespace": namespace,
            "mitre_technique": decision.mitre_technique,
            "trigger_reason": decision.reason,
            "execution_mode": "CONTROLLER_CLIENT_GO" if forensics else "CONTROLLER_NO_FORENSICS",
            "data_source": "cluster" if forensics else "none",
            "captured_at": (forensics or {}).get("captured_at"),
            "pod": {k: (forensics or {}).get(k) for k in ("phase", "node_name", "pod_ip", "labels")},
            "container_statuses": (forensics or {}).get("container_statuses") or [],
            "events": (forensics or {}).get("events") or [],
            "logs": logs,
            "process_tree": process_tree,
            "simulated_process_tree": process_tree,  # legacy key still read by the dashboard UI
            "active_sockets": [],
            "container_logs_snapshot": [line for lines in logs.values() for line in lines],
            "errors": errors,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def _result_from_controller(self, decision: GuardrailDecision, namespace: str,
                                resp: Dict[str, Any]) -> ActionExecutionResult:
        status, body = resp["http_status"], resp["body"]
        action, pod = decision.final_action, decision.target_pod
        if status == 200 and body.get("status") == "success" and str(body.get("mode", "")).lower() == "dry_run":
            # Brain is live but the controller is still in DRY_RUN: nothing was changed, so this is
            # neither a success nor something to verify (a rolled-out Deployment would pass verification).
            return ActionExecutionResult(
                success=False, action=action, target_pod=pod,
                details=("Go controller is in DRY_RUN mode, so nothing was changed. Set DRY_RUN=false on the "
                         "controller as well (both switches are required to go live)."),
                status_code="FAILED_CONTROLLER_DRY_RUN",
            )
        if status == 200 and body.get("status") == "success":
            forensics_file = None
            if action == "CILIUM_QUARANTINE_EBPF":
                forensics_file = self._persist_controller_forensics(decision, namespace, body.get("forensics"))
                self._record_quarantine_db(pod, namespace, decision.mitre_technique, decision.reason,
                                           forensics_file, body.get("policy_name"), active=True)
            elif action == "UNQUARANTINE_POD":
                self._record_quarantine_db(pod, namespace, active=False)
            workload = body.get("workload")
            health = True if action == "ESCALATE" else self.verify_remediation_health(pod, action, namespace, workload, use_kubectl=False)
            return ActionExecutionResult(
                success=True,
                action=action,
                target_pod=pod,
                details=f"[GO-CONTROLLER SERVICE] {body.get('message', '')}",
                status_code=f"COMPLETED_GO_{str(body.get('mode', 'REST')).upper()}",
                policy_applied={"name": body["policy_name"]} if body.get("policy_name") else None,
                forensics_file=forensics_file,
                health_verified=health,
                workload=workload,
            )
        if status == 200:
            code, why = "FAILED_CONTROLLER_SKIPPED", body.get("message") or "controller skipped the action"
        else:
            code = "FAILED_CONTROLLER_NOT_FOUND" if status == 404 else f"FAILED_CONTROLLER_{status}"
            why = body.get("error") or body.get("message") or f"controller returned HTTP {status}"
        return ActionExecutionResult(
            success=False, action=action, target_pod=pod,
            details=f"Go controller refused or failed the action: {why}", status_code=code,
        )

    def execute_decision(self, decision: GuardrailDecision) -> ActionExecutionResult:
        """
        Main execution router for a GuardrailDecision object.

        Live mode talks to the Go controller and fails closed when it is unreachable; the Python
        kubectl handlers only run in dry-run, or live when AEGIS_ALLOW_KUBECTL_FALLBACK=true.
        """
        namespace = decision.namespace or self.namespace

        # 1. Verify approval state
        if not decision.approved or decision.state != STATE_GUARDRAIL_APPROVED:
            logger.warning(
                f"CONTROLLER SKIP: Decision for pod '{decision.target_pod}' was not approved "
                f"(State: {decision.state}, Reason: {decision.reason})."
            )
            result = ActionExecutionResult(
                success=False,
                action=decision.final_action,
                target_pod=decision.target_pod,
                details=f"Execution skipped: Guardrail decision not approved. Reason: {decision.reason}",
                status_code="SKIPPED_NOT_APPROVED"
            )
            self._write_audit_log(decision, result)
            return result

        # ESCALATE only notifies a human; it never needs (and must not depend on) the controller.
        if not self.dry_run_mode and decision.final_action.upper() != "ESCALATE" and not decision.namespace:
            result = ActionExecutionResult(
                success=False,
                action=decision.final_action,
                target_pod=decision.target_pod,
                details="The decision has no namespace; refusing to act on a guessed namespace in live mode.",
                status_code="FAILED_NO_NAMESPACE",
            )
            self._write_audit_log(decision, result)
            return result

        if not self.dry_run_mode and decision.final_action.upper() != "ESCALATE":
            go_resp = self._dispatch_to_go_controller(decision, namespace)
            if go_resp is not None:
                result = self._result_from_controller(decision, namespace, go_resp)
                self._write_audit_log(decision, result)
                return result
            if not self._kubectl_fallback_allowed():
                result = ActionExecutionResult(
                    success=False,
                    action=decision.final_action,
                    target_pod=decision.target_pod,
                    details=(
                        "Go controller unreachable; refusing to act (fail closed). "
                        "Set AEGIS_ALLOW_KUBECTL_FALLBACK=true only for local development."
                    ),
                    status_code="FAILED_CONTROLLER_UNREACHABLE",
                )
                self._write_audit_log(decision, result)
                return result

        action = decision.final_action.upper()
        target_pod = decision.target_pod

        # Python handlers: dry-run, or the explicit local-development kubectl fallback
        if action == "RESTART_POD":
            result = self.restart_pod(target_pod, namespace=namespace, reason=decision.reason)
        elif action == "SCALE_DEPLOYMENT":
            result = self.scale_deployment(target_pod, namespace=namespace)
        elif action == "CILIUM_QUARANTINE_EBPF":
            result = self.quarantine_pod_ebpf(
                target_pod=target_pod,
                namespace=namespace,
                mitre_technique=decision.mitre_technique,
                reason=decision.reason
            )
        elif action == "UNQUARANTINE_POD":
            result = self.unquarantine_pod_ebpf(target_pod=target_pod, namespace=namespace)
        elif action == "ESCALATE":
            result = ActionExecutionResult(
                success=True,
                action="ESCALATE",
                target_pod=target_pod,
                details=f"Escalated to human operator on-call. Reason: {decision.reason}",
                status_code="ESCALATED_HUMAN"
            )
        else:
            result = ActionExecutionResult(
                success=False,
                action=action,
                target_pod=target_pod,
                details=f"Unknown or unsupported action type: {action}",
                status_code="FAILED_UNKNOWN_ACTION"
            )

        self._write_audit_log(decision, result)
        return result

    def _capture_dfir_forensics_snapshot(self, target_pod: str, mitre_technique: Optional[str],
                                         reason: Optional[str], namespace: Optional[str] = None) -> str:
        """
        Python-side snapshot used in dry-run and the opt-in kubectl fallback. It records only what
        it could actually collect; in dry-run there is no cluster, so the evidence lists are empty
        and the file says so (never an invented process tree).
        """
        ns = namespace or self.namespace
        os.makedirs(self.forensics_dir, exist_ok=True)
        forensics_file, _existing = self._forensics_target(target_pod)

        process_tree, sockets, errors = [], [], []
        mode = "DRY_RUN_NO_CLUSTER_DATA"

        if not self.dry_run_mode:
            mode = "LIVE_KUBECTL_EXEC"
            try:
                ps_res = subprocess.run(["kubectl", "exec", target_pod, "-n", ns, "--", "ps", "aux"],
                                        capture_output=True, text=True, timeout=5)
                if ps_res.returncode == 0:
                    process_tree = self._parse_process_list(ps_res.stdout)
                else:
                    errors.append(f"ps failed: {ps_res.stderr.strip()}")
            except Exception as e:
                errors.append(f"ps unavailable: {e}")
            try:
                net_res = subprocess.run(["kubectl", "exec", target_pod, "-n", ns, "--", "netstat", "-tuln"],
                                         capture_output=True, text=True, timeout=5)
                if net_res.returncode == 0:
                    for line in net_res.stdout.strip().split("\n")[2:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            sockets.append({"proto": parts[0], "local_address": parts[3],
                                            "state": parts[-1] if len(parts) > 5 else "LISTEN"})
                else:
                    errors.append(f"netstat failed: {net_res.stderr.strip()}")
            except Exception as e:
                errors.append(f"netstat unavailable: {e}")

        forensics_data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_pod": target_pod,
            "namespace": ns,
            "mitre_technique": mitre_technique,
            "trigger_reason": reason or "Falco eBPF security threat alert",
            "execution_mode": mode,
            "data_source": "cluster" if (process_tree or sockets) else "none",
            "process_tree": process_tree,
            "simulated_process_tree": process_tree,  # legacy key still read by the dashboard UI
            "active_sockets": sockets,
            "container_logs_snapshot": [],
            "errors": errors,
        }

        try:
            with open(forensics_file, "w", encoding="utf-8") as f:
                json.dump(forensics_data, f, indent=2)
            logger.info(f"DFIR Forensics snapshot saved to '{forensics_file}'.")
        except Exception as e:
            logger.error(f"Failed to write DFIR forensics snapshot: {e}")

        return forensics_file

    def _status_url(self) -> str:
        base = os.getenv("GO_CONTROLLER_URL", "http://localhost:8080/api/v1/reconcile").rstrip("/")
        if base.endswith("/reconcile"):
            base = base[: -len("/reconcile")]
        return base + "/status"

    @staticmethod
    def _rollout_complete(dep: Optional[Dict[str, Any]]) -> bool:
        """True only when the Deployment controller has acted on the latest spec AND every desired
        replica is updated and ready AND no old replica is still terminating."""
        if not dep:
            return False
        desired = dep.get("desired", 0)
        return (
            desired > 0
            and dep.get("observed_generation", 0) >= dep.get("generation", 0)
            and dep.get("updated") == desired
            and dep.get("ready") == desired
            and dep.get("replicas", desired) == desired
        )

    def _status_is_healthy(self, st: Dict[str, Any], action: str) -> bool:
        dep = st.get("deployment")
        if action in ("RESTART_POD", "SCALE_DEPLOYMENT"):
            if dep:
                return self._rollout_complete(dep)
            return bool(
                st.get("found") and st.get("phase") in ("Running", "Succeeded") and st.get("ready")
                and not st.get("terminating")  # the old pod still looks Ready during its grace period
            )
        if action == "CILIUM_QUARANTINE_EBPF":
            return bool(st.get("found") and st.get("quarantined"))
        if action == "UNQUARANTINE_POD":
            return not st.get("quarantined", False)
        return True

    def verify_remediation_health(self, target_pod: str, action: str, namespace: Optional[str] = None,
                                  workload: Optional[str] = None, timeout: Optional[float] = None,
                                  interval: Optional[float] = None, use_kubectl: Optional[bool] = None) -> bool:
        """
        Active post-remediation verification.

        Dry-run has no cluster to verify, so it reports True (and says so in the details).
        Live, it polls the controller's /status until the action's success condition holds or the
        timeout expires. Unreachable controller, errors and timeouts are all UNHEALTHY: "I could not
        check" is never reported as "it worked".
        """
        if self.dry_run_mode:
            return True
        if use_kubectl is None:
            # kubectl handlers (dev fallback) verify with kubectl; anything the CONTROLLER did is
            # verified through the controller (the brain may have no kubectl at all).
            use_kubectl = self._kubectl_fallback_allowed()
        if use_kubectl:
            return self._verify_via_kubectl(target_pod, action, namespace, workload)

        ns = namespace or self.namespace
        timeout = float(os.getenv("VERIFY_TIMEOUT_S", "90")) if timeout is None else timeout
        interval = float(os.getenv("VERIFY_INTERVAL_S", "5")) if interval is None else interval
        import requests

        token = os.getenv("GO_CONTROLLER_TOKEN", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        params = {"namespace": ns, "pod": target_pod}
        if workload:
            params["deployment"] = workload

        logger.info(f"VERIFY: waiting up to {timeout}s for '{target_pod}' ({action}) to be healthy.")
        deadline = time.monotonic() + timeout
        last = "no response"
        while True:
            try:
                resp = requests.get(self._status_url(), params=params, headers=headers, timeout=(3, 10))
                if resp.status_code == 200:
                    st = resp.json()
                    if self._status_is_healthy(st, action):
                        return True
                    last = f"not healthy yet: {st}"
                else:
                    last = f"controller status HTTP {resp.status_code}"
            except Exception as e:
                last = f"status check failed: {e}"
            if time.monotonic() >= deadline:
                logger.warning(f"VERIFY FAILED for '{target_pod}' after {action}: {last}")
                return False
            self._sleep(interval)

    def _verify_via_kubectl(self, target_pod: str, action: str, namespace: Optional[str],
                            workload: Optional[str]) -> bool:
        """Local-development fallback (AEGIS_ALLOW_KUBECTL_FALLBACK=true) when no controller exists."""
        ns = namespace or self.namespace
        if action in ("RESTART_POD", "SCALE_DEPLOYMENT"):
            ref = self._resolve_workload_ref(target_pod, ns)
            try:
                res = subprocess.run(["kubectl", "rollout", "status", ref, "-n", ns, "--timeout=60s"],
                                     capture_output=True, text=True, timeout=75)
                return res.returncode == 0
            except Exception as e:
                logger.warning(f"kubectl rollout status failed: {e}")
                return False
        if action in ("CILIUM_QUARANTINE_EBPF", "UNQUARANTINE_POD"):
            try:
                res = subprocess.run(
                    ["kubectl", "get", "ciliumnetworkpolicy", f"aegis-quarantine-{target_pod}", "-n", ns],
                    capture_output=True, text=True, timeout=10)
                exists = res.returncode == 0
            except Exception as e:
                logger.warning(f"kubectl get ciliumnetworkpolicy failed: {e}")
                return False
            return exists if action == "CILIUM_QUARANTINE_EBPF" else not exists
        return True

    def _write_audit_log(self, decision: GuardrailDecision, result: ActionExecutionResult):
        """Appends structured controller execution record to logs/controller_audit.jsonl and SQLite DB."""
        try:
            os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
            log_entry = {
                "timestamp": result.timestamp,
                "target_pod": decision.target_pod,
                "problem_type": decision.problem_type,
                "decision_state": decision.state,
                "approved_by_guardrails": decision.approved,
                "original_action": decision.original_action,
                "executed_action": result.action,
                "execution_success": result.success,
                "execution_status_code": result.status_code,
                "details": result.details,
                "mitre_technique": decision.mitre_technique,
                "dry_run": self.dry_run_mode,
                "policy_applied": result.policy_applied,
                "forensics_file": result.forensics_file,
                "health_verified": result.effective_health_verified()
            }
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write controller audit log file: {e}")

        # SQLite DB persistence
        try:
            from src.db.database import SessionLocal, init_db
            from src.db.models import AuditLogRecord
            init_db()
            with SessionLocal() as session:
                rec = AuditLogRecord(
                    timestamp=result.timestamp,
                    target_pod=decision.target_pod,
                    problem_type=decision.problem_type,
                    executed_action=result.action,
                    execution_success=result.success,
                    status_code=result.status_code,
                    details=result.details,
                    forensics_file=result.forensics_file,
                    health_verified=result.effective_health_verified()
                )
                session.add(rec)
                session.commit()
        except Exception as e:
            logger.debug(f"SQLite audit log write fallback: {e}")
