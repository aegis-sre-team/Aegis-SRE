# Aegis-SRE Phases 5-7 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (native, inline). Steps use checkbox (`- [ ]`) syntax. **No git commits until the user says so** (then: small atomic commits, single-line messages, no co-author trailer).

**Goal:** Make the heal/defend loop real and verifiable: a deployed Go controller executes approved actions (restart, scale, Cilium quarantine, unquarantine) with forensics; the brain verifies outcomes and escalates failures; the dashboard shows live cluster state; the test suite is green and deterministic.

**Architecture:** Go controller (`aegis-system`) is the only component that mutates the cluster. It re-checks safety (approved, allowlisted action, protected namespaces), captures real forensics before isolating, and exposes a status API. The Python brain/executor calls it over HTTP with a bearer token, ingests its forensics, verifies health by polling it, and escalates on failed verification. The dashboard reads live state from the controller + Prometheus and falls back to an explicitly labelled demo mode.

**Tech Stack:** Python 3.12 (FastAPI, SQLAlchemy, unittest), Go 1.27 (client-go v0.28.2, fake clientsets for tests), Cilium 1.16 CRDs, K3s v1.30.

**Spec:** `PHASES.md` (Phases 5-7 deliverables + success criteria) and the audit findings below.

## Audit findings driving this plan

| # | Finding | Fixed in |
|---|---|---|
| A1 | 7/35 tests fail at baseline: dashboard + benchmark tests hit real (dark) sensors so the fail-closed engine returns ESCALATE; all tests share one persistent DB so restart counters leak between runs | Task 1 |
| A2 | Namespace never travels brain -> executor (defaults `default`); Boutique is `online-boutique`, chaos is `aegis-chaos` | Tasks 2, 6 |
| A3 | No protection against actions on `kube-system`, `aegis-system`, `monitoring` | Tasks 2, 4 |
| A4 | Quarantine CNP uses `ingress: []`/`egress: []` (Cilium rejects rules with no rule bodies) and selects `io.kubernetes.pod.name` (not a Cilium endpoint label); allow-policies elsewhere would not be overridden by default-deny | Tasks 3, 4 |
| A5 | Forensics are partly invented (fabricated process tree/sockets) | Task 6 |
| A6 | Go and Python executors disagree (pod delete vs rollout restart; different name heuristics); Go quarantine not idempotent; Go path captures forensics after the cut and skips DB recording | Tasks 4, 6 |
| A7 | Brain pod has no kubectl/RBAC; controller has no image or manifests | Tasks 4, 5 |
| A8 | `verify_remediation_health` returns True when the pod lookup fails | Task 7 |
| A9 | Webhook only diagnoses; nothing acts or escalates automatically | Task 7 |
| A10 | Dashboard data is simulated; startup logs claim sensors are connected; forensics endpoint fabricates data; HITL restart/scale only mutate the in-memory store | Task 8 |

## Global Constraints

- Allowed actions stay `RESTART_POD, SCALE_DEPLOYMENT, CILIUM_QUARANTINE_EBPF, UNQUARANTINE_POD, ESCALATE`; blocklist unchanged.
- Protected namespaces (never mutated): `kube-system, kube-public, kube-node-lease, aegis-system, monitoring, cilium-secrets`.
- Live execution needs BOTH `AEGIS_DRY_RUN=false` (brain) and `DRY_RUN=false` (controller); both default `true`.
- Quarantine label key `aegis.io/quarantine-target`; label value = pod name if <=63 chars and valid, else first 52 chars + `-` + first 10 hex of sha256(pod name). Python and Go must produce identical values.
- Quarantine policy name `aegis-quarantine-<pod>` (unchanged), using `ingressDeny`/`egressDeny` with `fromEntities`/`toEntities: ["all"]`.
- Controller auth: `Authorization: Bearer $CONTROLLER_TOKEN` when the token env is set.
- Images are linux/arm64, shipped as tarballs (no registry). Commit style per CLAUDE.md.
- No invented data: absent evidence is reported as absent.

## Review Focus

1. Pod name longer than 63 chars -> label value hashed, identical in Go and Python.
2. Quarantine applied twice to the same pod -> second call succeeds (idempotent), one policy.
3. Missing or protected namespace -> rejected before any cluster call.
4. Live mode with controller unreachable -> fail closed (FAILED, escalate), never a silent success or kubectl fallback.
5. Target pod deleted between diagnosis and action -> explicit not-found error, never success; forensics failure must not block isolation.

## File Structure

- `test/support.py` (new): env isolation (temp DB, no cloud LLM, closed Ollama port) + `sensor_patches` helper. Imported first by every test module.
- `src/guardrails/action_schema.py`, `validator.py`: namespace field + protected-namespace policy.
- `src/controller/cilium_policy.py`: label-based deny-all policy + `quarantine_label_value`.
- `controller/`: `types.go`, `safety.go`, `workload.go`, `quarantine.go`, `forensics.go`, `exec.go`, `server.go`, `main.go` + `*_test.go`, `Dockerfile`.
- `k8s/controller/controller.yaml` (new), `k8s/brain/brain.yaml` (env), `aws/*` (controller image + token).
- `src/controller/executor.py`: namespace-aware, controller-first, fail-closed, real forensics only.
- `src/brain/remediation.py` (new): `process_alert` pipeline (diagnose -> guard -> execute -> verify -> escalate); `src/brain/main.py` uses it.
- `src/dashboard/live_state.py` (new) + `server.py`: live/demo modes, DB event stream, honest health, real HITL.
- Docs: `PHASES.md`, `CLAUDE.md`, `README.md`, `k8s/PHASE5_VERIFY.md`, `PHASE6_VERIFY.md`, `PHASE7_VERIFY.md`.

---

### Task 1: Test isolation and deterministic sensors (fixes A1)

**Files:** Create `test/support.py`, `test/conftest.py`; Modify every `test/test_*.py` (first import `import support`), `test/test_dashboard.py`, `test/test_chaos_benchmark.py`.

**Interfaces:**
- Produces: `support.sensor_patches(engine, metrics=None, falco_events=None, logs=None) -> list[unittest.mock._patch]`; `support.start_patches(testcase, patches) -> None` (starts + registers cleanup); importing `support` sets `DATABASE_URL=sqlite:///<tmp>/aegis_test.db`, `AEGIS_DB_DIR=<tmp>`, `GROQ_API_KEY=""`, `GEMINI_API_KEY=""`, `OLLAMA_HOST=http://127.0.0.1:9`.

- [ ] Step 1: Run the suite to record the baseline (7 failures) in the scratchpad.
- [ ] Step 2: Implement `support.py` per the interface; default metrics must model a healthy-but-erroring pod, `falco_events` default `[]`.
- [ ] Step 3: Import `support` first in each test module; in dashboard/benchmark/pipeline tests start `sensor_patches` against the engine instances the code under test uses (`src.dashboard.server.diagnostic_engine`, benchmark `cls.diagnostic_engine`).
- [ ] Step 4: Add `test_isolation.py::test_database_is_temp` asserting `DATABASE_URL` points outside `logs/` and `test_llm_has_no_cloud_keys` asserting empty keys.
- [ ] Step 5: Run full suite twice back to back. Expected: 0 failures both times, runtime far below 170s.
- [ ] Step 6: Verify and correct the single-test command documented in CLAUDE.md (stdlib `test` package may shadow `test.test_x`).

### Task 2: Namespace-aware guardrails (A2, A3)

**Files:** Modify `src/guardrails/action_schema.py`, `src/guardrails/validator.py`, `src/brain/diagnostic_engine.py`, `src/brain/main.py` (webhook passes `labels["namespace"]`); Test `test/test_guardrails.py` (+ new cases).

**Interfaces:**
- Produces: `PROTECTED_NAMESPACES: Set[str]`; `GuardrailDecision.namespace: Optional[str] = None`; `LLMVerdictSchema.namespace`, `ControllerDecisionSchema.namespace` (Optional[str]); `DiagnosticEngine.diagnose_incident(pod_name, alert_type, fail_closed=True, namespace: Optional[str]=None)` stores `verdict["namespace"]`; env `AEGIS_ALLOWED_NAMESPACES` (comma list, optional allowlist).

- [ ] Step 1: Failing tests: `test_protected_namespace_rejected_for_restart`, `..._for_quarantine` (state `STATE_ACTION_REJECTED`, `final_action=="ESCALATE"`), `test_escalate_allowed_in_protected_namespace`, `test_allowlist_env_blocks_other_namespaces` (uses `mock.patch.dict(os.environ)`), `test_namespace_propagates_to_decision` (decision.namespace == "online-boutique").
- [ ] Step 2: Implement; the check runs after blocklist/allowlist and before confidence; mutating actions only.
- [ ] Step 3: Thread `namespace` through `diagnose_incident` and the webhook; `_escalate_dark` carries it too.
- [ ] Step 4: Run `test_guardrails.py` and `test_pipeline.py`; all pass.

### Task 3: Cilium quarantine policy rewrite (A4, Python side)

**Files:** Modify `src/controller/cilium_policy.py`; Test `test/test_controller.py`.

**Interfaces:**
- Produces: `quarantine_label_value(pod_name: str) -> str`; `QUARANTINE_LABEL = "aegis.io/quarantine-target"`; `generate_cilium_quarantine_policy` keeps its signature and now emits `endpointSelector.matchLabels == {QUARANTINE_LABEL: quarantine_label_value(pod)}`, `ingressDeny == [{"fromEntities": ["all"]}]`, `egressDeny == [{"toEntities": ["all"]}]`, no `ingress`/`egress` keys.

- [ ] Step 1: Failing tests: `test_label_value_short_name_unchanged`, `test_label_value_long_name_is_63_chars_and_stable` (fixed vector: 80-char name -> expected 52+1+10 string computed by hand-checked sha256), `test_policy_uses_deny_rules_not_empty_lists`, `test_policy_selector_uses_quarantine_label`.
- [ ] Step 2: Implement; update `generate_unquarantine_spec` consistently.
- [ ] Step 3: Run `test_controller.py`; pass.

### Task 4: Go controller core: safety, restart, scale (A3, A6)

**Files:** Create `controller/types.go`, `safety.go`, `workload.go`, `safety_test.go`, `workload_test.go`; Modify `reconciler.go` (becomes dispatcher), `go.mod` (+ `go.sum` via tidy).

**Interfaces:**
- Produces: `type ActionRequest struct{Approved bool; FinalAction, TargetPod, Namespace, ProblemType, MitreTechnique, Reason string; Replicas *int32}` (JSON tags as today, `replicas,omitempty`); `type ActionResult struct{Status, Mode, Action, Target, Namespace, Message, PolicyName string; Forensics *Forensics}`; sentinel errors `ErrNotApproved, ErrProtectedNamespace, ErrNamespaceRequired, ErrUnsupportedAction, ErrNotFound`; `func validateRequest(req ActionRequest, allowed map[string]bool) error`; `func (r *ActionReconciler) Reconcile(ctx, req) (ActionResult, error)`; `ActionReconciler` gains `DryRun bool`, `MaxReplicas int32`, `AllowedNamespaces map[string]bool`.
- Behavior: restart resolves Pod -> ReplicaSet -> Deployment and patches `spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"]`; no Deployment owner -> delete the pod. Scale target = request replicas else current+1, capped at `MaxReplicas` (default 4).

- [ ] Step 1: Install deps: `go mod tidy` (needs network).
- [ ] Step 2: Failing tests with `fake.NewSimpleClientset`: `TestValidateRejectsUnapproved`, `TestValidateRejectsProtectedNamespaces` (table over all six), `TestValidateRejectsEmptyNamespace`, `TestRestartPatchesOwningDeployment`, `TestRestartBarePodDeletesIt`, `TestRestartMissingPodReturnsNotFound`, `TestScaleDefaultsToCurrentPlusOneCapped`, `TestScaleHonoursExplicitReplicasUpToCap`, `TestDryRunMutatesNothing` (assert no actions with verbs patch/update/delete/create on the fake).
- [ ] Step 3: Implement; run `go vet ./... && go test ./...`. Expected: PASS.

### Task 5: Go controller quarantine, forensics, status, HTTP server (A4, A6, Review Focus 2, 5)

**Files:** Create `controller/quarantine.go`, `forensics.go`, `exec.go`, `server.go`, `*_test.go`; Modify `main.go` (thin: build clients, `newServer(...)`, listen).

**Interfaces:**
- Produces: `func QuarantineLabelValue(pod string) string` (same algorithm as Python); `type Forensics struct{CapturedAt, Pod, Namespace string; Phase, NodeName, PodIP string; Labels map[string]string; ContainerStatuses []ContainerSummary; Events []string; Logs map[string][]string; ProcessList *string; Errors []string}`; `type PodStatus struct{Found bool; Phase string; Ready bool; Restarts int32; Quarantined bool; Deployment *DeploymentStatus}` and `DeploymentStatus{Name string; Desired, Ready, Updated int32}`; `func (r *ActionReconciler) Status(ctx, ns, pod string) (PodStatus, error)`; `func newServer(r *ActionReconciler, token string) http.Handler` routes: `GET /healthz`, `POST /api/v1/reconcile`, `GET /api/v1/status?namespace=&pod=`, `GET /api/v1/pods?namespace=`.
- Behavior: quarantine order = verify pod -> forensics (best-effort, errors recorded, never blocks) -> label patch -> CNP create-or-update (deny rules per Global Constraints). Unquarantine deletes CNP (NotFound ok) and removes the label. `Exec` is an optional func field; nil -> `ProcessList=nil` plus error note. Auth: missing/invalid bearer -> 401 when token set. Status codes: validation -> 400, protected ns -> 403, unapproved -> 200 `status:"skipped"`, not found -> 404, other -> 500.

- [ ] Step 1: Failing tests (fake kube + fake dynamic client with `ciliumnetworkpolicies` registered): `TestQuarantineCreatesDenyPolicyAndLabelsPod`, `TestQuarantineTwiceIsIdempotent`, `TestQuarantineCapturesForensicsBeforeLabel` (action ordering on the fake), `TestQuarantineProceedsWhenForensicsLogsFail`, `TestQuarantineMissingPodNotFound`, `TestUnquarantineRemovesPolicyAndLabel`, `TestUnquarantineWithoutPolicyIsOK`, `TestLabelValueLongNameMatchesPythonVector`, `TestServerRequiresBearerToken`, `TestServerStatusCodes` (table), `TestStatusReportsDeploymentRollout`.
- [ ] Step 2: Implement; real SPDY exec in `exec.go` compiles but is only exercised live.
- [ ] Step 3: `go vet ./... && go test ./... -race` (race only if cgo available; else without). Expected: PASS.

### Task 6: Controller packaging and deployment (A7)

**Files:** Create `controller/Dockerfile`, `k8s/controller/controller.yaml`, `k8s/PHASE5_VERIFY.md`; Modify `k8s/brain/brain.yaml`, `aws/push-image.sh` (component arg `brain|controller`, default brain), `aws/apply-stack.sh` (generate `aegis-controller-token` secret once; push + apply controller before brain), `.dockerignore` as needed.

**Interfaces:**
- Produces: Service `aegis-controller.aegis-system.svc:8080`; ServiceAccount `aegis-controller`; ClusterRole verbs limited to: pods `get,list,patch,delete`; pods/log `get`; pods/exec `create`; events `list`; replicasets `get`; deployments `get,list,patch`; deployments/scale `get,update`; `cilium.io` `ciliumnetworkpolicies` `get,list,create,update,patch,delete`. Controller env `DRY_RUN=true`, `MAX_REPLICAS=4`, `CONTROLLER_TOKEN` (secretKeyRef `aegis-controller-token`), brain env `GO_CONTROLLER_URL`, `GO_CONTROLLER_TOKEN`.
- Image tag `aegis-controller:phase5`, built `--platform linux/arm64`.

- [ ] Step 1: Write manifests + Dockerfile (multi-stage, `CGO_ENABLED=0`, non-root, distroless/alpine).
- [ ] Step 2: Validate: `kubectl apply --dry-run=client` if kubectl exists, else parse with `python -c yaml.safe_load_all`; `docker build` the controller for the host arch to prove the Dockerfile compiles.
- [ ] Step 3: Extend `aws/push-image.sh` and `apply-stack.sh`; `bash -n` all scripts.
- [ ] Step 4: Write `PHASE5_VERIFY.md`: dry-run first, then live restart/scale/quarantine/unquarantine with exact commands and expected outputs, plus the Cilium deny-policy check (`cilium policy get`, curl from another pod fails) that could not be tested offline.

### Task 7: Python executor integration (A5, A6, Review Focus 4)

**Files:** Modify `src/controller/executor.py`, `src/brain/main.py` (dry-run env), `test/test_controller.py`, new `test/test_executor_controller.py`.

**Interfaces:**
- Consumes: Task 5 HTTP API, Task 2 `decision.namespace`.
- Produces: `ActionExecutor._dispatch_to_go_controller(decision) -> Optional[Dict]` sends bearer token (`GO_CONTROLLER_TOKEN`) and `decision.namespace or self.namespace`; live + controller unreachable -> `ActionExecutionResult(success=False, status_code="FAILED_CONTROLLER_UNREACHABLE")` unless `AEGIS_ALLOW_KUBECTL_FALLBACK=true`; quarantine success writes the controller's forensics JSON to `logs/forensics_<pod>.json` and calls `_record_quarantine_db`; fabricated process tree/sockets removed - dry-run snapshot has `"execution_mode": "DRY_RUN_NO_CLUSTER_DATA"` and empty lists.

- [ ] Step 1: Failing tests using `mock.patch("requests.post")` and `requests.get`: `test_live_dispatch_sends_namespace_and_token`, `test_live_unreachable_controller_fails_closed`, `test_kubectl_fallback_only_when_opted_in`, `test_quarantine_persists_controller_forensics_and_db_record`, `test_dry_run_forensics_contain_no_invented_processes`, `test_not_found_from_controller_is_failure`.
- [ ] Step 2: Implement; keep dry-run behavior and status codes unchanged for existing tests.
- [ ] Step 3: Run `test_controller.py`, `test_executor_controller.py`, `test_pipeline.py`.

### Task 8: Verify -> escalate loop (Phase 6, A8, A9)

**Files:** Create `src/brain/remediation.py`, `test/test_remediation_loop.py`, `k8s/PHASE6_VERIFY.md`; Modify `src/controller/executor.py` (`verify_remediation_health`), `src/brain/main.py` (webhook + `/remediate` use the pipeline), `src/brain/notifications.py` only if its signature blocks escalation reuse.

**Interfaces:**
- Produces: `executor.verify_remediation_health(target_pod, action, namespace=None, timeout=None, interval=None) -> bool` - dry-run: `True`; live: polls controller `/api/v1/status` until healthy or `VERIFY_TIMEOUT_S` (default 90, interval 5); not-found counts healthy only for RESTART/SCALE when the owning Deployment has `Ready==Desired && Updated==Desired`; quarantine requires `Quarantined==true`; controller unreachable or timeout -> `False`. `remediation.process_alert(engine, executor, notifier, pod_name, alert_type, namespace=None) -> Dict` returning `{verdict, decision, execution, verified: bool, escalated: bool, escalation: Optional[dict]}`; escalates (state `STATE_ESCALATE_HUMAN`, notifier called) when the decision was not approved OR execution failed OR verification failed. Webhook auto-acts only when `AEGIS_AUTO_REMEDIATE=true` (default false = diagnose only, as today).

- [ ] Step 1: Failing tests (fake executor/engine objects): `test_bug_path_restart_verified_no_escalation`, `test_attack_path_quarantine_verified`, `test_failed_verification_escalates_and_notifies`, `test_failed_execution_escalates`, `test_unapproved_decision_escalates_without_executing`, `test_verify_pod_gone_but_deployment_rolled_out_is_healthy`, `test_verify_pod_gone_without_rollout_is_unhealthy`, `test_verify_controller_unreachable_is_unhealthy`, `test_webhook_does_not_act_unless_auto_remediate`.
- [ ] Step 2: Implement; run new tests + full suite.
- [ ] Step 3: Write `PHASE6_VERIFY.md` (chaos -> alert -> act -> verify on real cluster, plus forced-failure escalation drill).

### Task 9: Live dashboard (Phase 7, A10)

**Files:** Create `src/dashboard/live_state.py`, `test/test_live_state.py`, `k8s/PHASE7_VERIFY.md`; Modify `src/dashboard/server.py`, `src/dashboard/static/app.js` + `index.html` (data-source badge), `test/test_dashboard.py`.

**Interfaces:**
- Produces: `class LiveClusterState(controller_url, prometheus_url, namespaces, token=None)` with `snapshot() -> {"data_source": "live", "pods": [...], "sensors": {...}}` (pods from controller `/api/v1/pods`, cpu/mem from Prometheus cAdvisor queries, failures reported not faked); `DASHBOARD_MODE` env `auto|demo|live` (auto = live iff controller answers `/healthz`); every telemetry payload carries `data_source`; `/api/v1/forensics/{pod}` returns 404 JSON when no real file exists in live mode (demo mode keeps sample data tagged `"demo": true`); lifespan logs derive from `collector.check_sensors()`; HITL RESTART/SCALE call `action_executor`; DB event stream: broadcast loop emits `PIPELINE_EVENT` for audit/incident rows newer than the last seen id.

- [ ] Step 1: Failing tests: `test_live_snapshot_maps_controller_pods_and_prometheus`, `test_live_snapshot_reports_prometheus_down_without_fake_metrics`, `test_mode_auto_falls_back_to_demo`, `test_payload_includes_data_source`, `test_forensics_404_in_live_mode`, `test_hitl_restart_calls_executor`, `test_pipeline_event_emitted_for_new_audit_row`.
- [ ] Step 2: Implement; keep existing demo-mode tests green (they run in demo mode via `support`).
- [ ] Step 3: Minimal UI change: show `data_source` badge; no redesign.
- [ ] Step 4: Write `PHASE7_VERIFY.md`.

### Task 10: Docs, final verification, handoff

**Files:** Modify `PHASES.md` (statuses: built-offline vs verified-live, unchecked criteria stay unchecked), `CLAUDE.md` (controller, modes, env vars, test commands), `README.md`/`aws/README.md` (controller image, token, AWS), `k8s/PHASE2/3_VERIFY.md` context line.

- [ ] Step 1: Full verification: `python -m unittest discover -s test -p "test_*.py"` twice; `cd controller && go vet ./... && go test ./...`; `bash -n aws/*.sh`; YAML parse of every new manifest.
- [ ] Step 2: Self-review diff against the Review Focus list and A1-A10; list what remains unverified live.
- [ ] Step 3: Report to the user: what is built, what is only offline-verified, exact first-AWS-session checklist. Do not commit.

## Self-review

- Coverage: A1->T1, A2->T2/T7, A3->T2/T4, A4->T3/T5, A5->T7, A6->T4/T5/T7, A7->T6, A8/A9->T8, A10->T9; Review Focus 1->T3/T5, 2->T5, 3->T2/T4, 4->T7, 5->T5.
- Type consistency: `namespace` is `Optional[str]` everywhere in Python and `string` in Go; label algorithm lives in Global Constraints and is tested in both languages with the same vector; `ActionResult.Forensics` JSON keys are what T7 persists.
- Honest limits: Cilium deny semantics, SPDY exec, RBAC sufficiency, and traffic-block proof cannot be verified without the AWS cluster; they are captured in `PHASE5_VERIFY.md`.
