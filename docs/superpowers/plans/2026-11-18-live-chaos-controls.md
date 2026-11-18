# Live Chaos Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start and stop eight chaos scenarios on the live cluster from the React console, and make real escalations show on the Review page.

**Architecture:** The Go controller gets one tightly limited chaos endpoint (fixed allowlist, `aegis-chaos` only, off unless `CHAOS_ENABLED=true`, auto-stop janitor). The dashboard proxies to it in live mode. The brain records escalations in the shared database and the dashboard reads the Review list from there in live mode.

**Tech Stack:** Go + client-go (fake clientset tests), Python 3.12 + FastAPI + SQLAlchemy + unittest, React + TypeScript + Vite + vitest.

**Spec:** `docs/superpowers/specs/2026-11-18-live-chaos-controls-design.md`

## Global Constraints

- The Go controller is the only component that changes the cluster. The dashboard never talks to the Kubernetes API.
- Chaos namespace is hard-coded to `aegis-chaos`. Scenario ids and deployments come from one fixed map; nothing from a request is used as a name.
- `CHAOS_ENABLED` defaults to `false`. Chaos never depends on or changes `DRY_RUN`.
- Time limit: default 30 minutes, maximum 120. Annotation key `aegis.io/chaos-expires-at` (RFC 3339, UTC).
- No change to guardrail actions, prompts, quarantine design or the AWS scripts. Remediation stays dry-run.
- Demo mode keeps today's simulator and in-memory escalations.
- Controller routes need the same bearer token as the others. Dashboard action routes need `AEGIS_DASHBOARD_TOKEN` when it is set.
- Commit messages are one line, no body, no trailer. Never commit `logs/guardrail_audit.jsonl`.
- Python: run from the repo root with `PYTHONPATH=.`; `test/support.py` is the first import of every test module. Go: `cd controller && go vet ./... && go test ./...`. Frontend: `cd frontend && npx vitest run && npx tsc --noEmit`.

Scenario map (id -> deployment), used by every task:

| id | deployment |
|---|---|
| `cpu-spike` | `chaos-cpu-spike` |
| `oom` | `chaos-oom` |
| `crashloop` | `chaos-crashloop` |
| `http-500` | `chaos-http-500` |
| `shell-injection` | `chaos-shell-injection` |
| `credential-read` | `chaos-credential-read` |
| `network-recon` | `chaos-network-recon` |
| `restart-storm` | `chaos-restart-storm` |

## Review Focus

1. Unknown scenario id (also `../x`, empty, wrong case): rejected with 400 before any cluster call.
2. `CHAOS_ENABLED` unset or false: 403 and zero cluster calls, on both GET-with-mutation and POST.
3. `ttl_minutes` of 0, negative, or 100000: 0 means default 30, negative is 400, above 120 clamps to 120.
4. Start twice, or stop a stopped scenario: both succeed and change nothing else (start refreshes the expiry).
5. Scenario manifest not applied yet: 404 "not installed" for that scenario, and the list marks it `installed: false` instead of failing the whole list.
6. Controller unreachable from the dashboard: 502 with a clear message, never a stale "Running".
7. The same escalation recorded twice, or resolving an unknown incident id: no duplicate rows, no crash.
8. Unparsable or missing expiry annotation on a running scenario: the janitor stops it (fail toward stopping).

---

### Task 1: Controller chaos core

**Files:**
- Create: `controller/chaos.go`, `controller/chaos_test.go`
- Modify: `controller/types.go` (new sentinel errors), `controller/reconciler.go` (new field `ChaosEnabled bool`)

**Interfaces:**
- Produces (later tasks rely on these exact names):
  - `const chaosNamespace = "aegis-chaos"`, `const chaosExpiresAnnotation = "aegis.io/chaos-expires-at"`, `const defaultChaosTTL = 30`, `const maxChaosTTL = 120`
  - `var chaosScenarios = map[string]string{...}` (the table above)
  - errors in `types.go`: `ErrChaosDisabled`, `ErrUnknownScenario`, `ErrInvalidChaosState`, `ErrInvalidTTL`
  - `type ChaosScenario struct { ID string \`json:"id"\`; Deployment string \`json:"deployment"\`; Installed bool \`json:"installed"\`; Replicas int32 \`json:"replicas"\`; Ready int32 \`json:"ready"\`; ExpiresAt string \`json:"expires_at,omitempty"\` }`
  - `type ChaosRequest struct { Scenario string \`json:"scenario"\`; State string \`json:"state"\`; TTLMinutes int \`json:"ttl_minutes,omitempty"\` }`
  - `func (r *ActionReconciler) ListChaos(ctx context.Context) ([]ChaosScenario, error)` (sorted by id; a missing deployment gives `Installed:false`, not an error)
  - `func (r *ActionReconciler) SetChaos(ctx context.Context, req ChaosRequest) (ChaosScenario, error)`
  - `func (r *ActionReconciler) StopExpiredChaos(ctx context.Context) (int, error)` (returns how many it stopped)
  - `func (r *ActionReconciler) RunChaosJanitor(ctx context.Context, every time.Duration)` (loops until ctx is done)

- [ ] **Step 1: Write the failing tests** in `chaos_test.go`, using `fake.NewSimpleClientset` with one Deployment per scenario in `aegis-chaos` at 0 replicas and `r.ChaosEnabled = true`. Test names and assertions:
  - `TestSetChaosOnScalesToOneAndSetsExpiry`: state `on` gives replicas 1 and an annotation about 30 minutes ahead (use `r.Now`).
  - `TestSetChaosOffScalesToZeroAndClearsAnnotation`.
  - `TestSetChaosRejectsUnknownScenarioWithoutClusterCalls`: ids `""`, `"../x"`, `"CPU-SPIKE"`, `"chaos-cpu-spike"` all return `ErrUnknownScenario` and `len(cs.Actions())==0`.
  - `TestSetChaosDisabledMakesNoClusterCalls`: `ChaosEnabled=false` returns `ErrChaosDisabled`, `len(cs.Actions())==0`; same for `ListChaos`.
  - `TestSetChaosTTLRules`: 0 uses 30; 45 uses 45; 100000 clamps to 120; -1 returns `ErrInvalidTTL`.
  - `TestSetChaosInvalidState`: `"maybe"` returns `ErrInvalidChaosState`.
  - `TestSetChaosIsIdempotent`: on twice leaves replicas 1 and moves the expiry later; off twice succeeds.
  - `TestSetChaosMissingDeploymentIsNotFound`: returns an error satisfying `errors.Is(err, ErrNotFound)`.
  - `TestListChaosMarksUninstalledScenarios`: only 3 deployments created, the other 5 have `Installed:false`, no error, sorted by id.
  - `TestStopExpiredChaos`: one expired, one future, one running with a garbage annotation, one running with no annotation; returns 3 stopped, the future one stays at 1.
- [ ] **Step 2: Run** `cd controller && go test ./... -run Chaos`. Expected: FAIL (undefined symbols).
- [ ] **Step 3: Implement** the interface above. Use `Deployments(chaosNamespace).Get` then `Update` (the Role has `get/list/update`; do not use a scale subresource or `Patch`). Check `ChaosEnabled` first in `ListChaos` and `SetChaos`. Wrap missing deployments as `fmt.Errorf("%w: %s", ErrNotFound, name)`.
- [ ] **Step 4: Run** `cd controller && go vet ./... && go test ./...`. Expected: PASS.
- [ ] **Step 5: Commit** `git add controller && git commit -m "feat(controller): add a guarded chaos scenario switch with auto-stop"`

### Task 2: Controller HTTP routes and wiring

**Files:**
- Modify: `controller/server.go` (routes and `httpStatusFor`), `controller/main.go` (env + janitor), `controller/server_test.go`
- Modify: `k8s/controller/controller.yaml` (env `CHAOS_ENABLED: "false"`)

**Interfaces:**
- Consumes: everything produced by Task 1.
- Produces: `GET /api/v1/chaos` returns `{"scenarios":[ChaosScenario...]}`; `POST /api/v1/chaos` with a `ChaosRequest` body returns the updated `ChaosScenario`. Status mapping: `ErrChaosDisabled` 403, `ErrUnknownScenario`/`ErrInvalidChaosState`/`ErrInvalidTTL` 400, `ErrNotFound` 404 (already mapped).

- [ ] **Step 1: Write failing tests** in `server_test.go`: `TestChaosRoutesRequireToken` (401 without bearer); `TestChaosDisabledReturns403`; `TestChaosStartStopRoundTrip` (POST on gives 200 and replicas 1, GET shows it, POST off gives 0); `TestChaosUnknownScenarioReturns400`; `TestChaosMissingDeploymentReturns404`; `TestChaosWorksWhileDryRunIsTrue` (`r.DryRun=true`, still scales: chaos is independent of dry-run).
- [ ] **Step 2: Run** `go test ./... -run Chaos`. Expected: FAIL.
- [ ] **Step 3: Implement** the two routes inside `newServer` behind `protect` (reject other methods with 405, limit the body to 1 MiB like `/reconcile`); extend `httpStatusFor`; in `main.go` read `CHAOS_ENABLED` (true only for the literal `true`, case-insensitive) into `r.ChaosEnabled`, and when enabled start `go r.RunChaosJanitor(ctx, 30*time.Second)`; log one line saying chaos is enabled or disabled. Add the env var to the Deployment in `k8s/controller/controller.yaml` with value `"false"`.
- [ ] **Step 4: Run** `cd controller && go vet ./... && go test ./...`. Expected: PASS.
- [ ] **Step 5: Commit** `git add controller k8s/controller && git commit -m "feat(controller): expose the chaos switch over a token-protected API"`

### Task 3: The three new scenarios

**Files:**
- Create: `k8s/chaos/chaos-credential-read.yaml`, `k8s/chaos/chaos-network-recon.yaml`, `k8s/chaos/chaos-restart-storm.yaml`, `test/test_chaos_manifests.py`

**Interfaces:**
- Produces: three Deployments in `aegis-chaos` at `replicas: 0`, named per the table, each with its own ServiceAccount (`automountServiceAccountToken: false`), `busybox:1.36`, small requests and limits, labels `app`, `aegis.io/chaos`, `aegis.io/mitre`, in the style of `k8s/chaos/chaos-shell-injection.yaml`.

- [ ] **Step 1: Write the failing test** `test/test_chaos_manifests.py` (first import `test.support`): parse every `k8s/chaos/*.yaml` with `yaml.safe_load_all`; assert the eight deployment names from the table all exist, each in namespace `aegis-chaos`, each `spec.replicas == 0`, each container has a memory limit, none mounts a secret, none has `hostNetwork`/`hostPID`/`privileged`. Name: `test_every_scenario_manifest_is_present_and_safe`.
- [ ] **Step 2: Run** `PYTHONPATH=. python -m unittest discover -s test -p "test_chaos_manifests.py"`. Expected: FAIL (3 missing).
- [ ] **Step 3: Write the manifests.** `credential-read`: loop that does `cat /etc/shadow >/dev/null` then `sleep 20` (Falco rule `Aegis Sensitive File Read`, T1552). `network-recon`: loop that runs `nc -z -w 1 10.43.0.1 443` then `sleep 20` (Falco rule `Aegis Network Discovery Tool Spawned`, T1046). `restart-storm`: `echo up; sleep 20; exit 1` (starts fine, fails about 20 s later). Add a short comment in each saying which detector fires and the expected outcome.
- [ ] **Step 4: Run** the test again. Expected: PASS.
- [ ] **Step 5: Commit** `git add k8s/chaos test/test_chaos_manifests.py && git commit -m "feat(chaos): add credential-read, network-recon and restart-storm scenarios"`

### Task 4: Persist escalations in the database

**Files:**
- Create: `src/db/escalations.py`, `test/test_escalations.py`
- Modify: `src/brain/remediation.py` (record the escalation), `test/test_remediation.py` if it exists, otherwise cover it in the new test file

**Interfaces:**
- Produces in `src/db/escalations.py`:
  - `def mark_escalated(verdict: dict, reason: str, namespace: Optional[str] = None) -> bool` upserts: updates the newest `IncidentRecord` with `verdict["incident_id"]` (status `ESCALATED`, `guardrail_approved=False`, `guardrail_reason=reason`, `final_action="ESCALATE"`), or inserts one from the verdict if none exists. Never raises (returns False on DB failure). Repeated calls for the same incident id keep one row.
  - `def list_open_escalations(limit: int = 50) -> List[dict]` returns dicts shaped for the UI `Escalation` type: `incident_id, target_pod, problem_type, confidence, reason, mitre_technique, timestamp` for rows with status `ESCALATED`, newest first.
  - `def resolve_escalation_record(incident_id: str) -> bool` sets matching `ESCALATED` rows to `RESOLVED`; False when none match.

- [ ] **Step 1: Write failing tests** (`test/test_escalations.py`, temp SQLite via `configure_database`): `test_mark_escalated_inserts_when_the_incident_was_never_persisted` (the `_escalate_dark` case); `test_mark_escalated_updates_existing_open_row`; `test_mark_escalated_twice_keeps_one_row`; `test_list_open_escalations_shape_and_order`; `test_resolve_moves_it_out_of_the_list`; `test_resolve_unknown_id_returns_false`; `test_mark_escalated_survives_a_broken_database` (patch `SessionLocal` to raise; returns False, no exception); and `test_process_alert_records_escalation` (call `process_alert` with a stub engine returning an unapproved decision and a stub notifier, then assert `list_open_escalations()` has the pod).
- [ ] **Step 2: Run** `PYTHONPATH=. python -m unittest discover -s test -p "test_escalations.py"`. Expected: FAIL.
- [ ] **Step 3: Implement** the three functions, and in `process_alert` call `mark_escalated(clean_verdict, escalation_reason, namespace)` right after `dispatch_escalation` (only when escalating).
- [ ] **Step 4: Run** the new tests, then the whole suite: `PYTHONPATH=. python -m unittest discover -s test -p "test_*.py"`. Expected: PASS; then `git checkout -- logs/guardrail_audit.jsonl`.
- [ ] **Step 5: Commit** `git add src test && git commit -m "feat(brain): record escalations in the shared database"`

### Task 5: Dashboard chaos endpoints and database-backed Review

**Files:**
- Create: `src/dashboard/chaos_client.py`, `test/test_dashboard_chaos.py`
- Modify: `src/dashboard/server.py`

**Interfaces:**
- Consumes: Task 2 routes; Task 4 functions.
- Produces in `chaos_client.py`: `class ChaosClient` with `__init__(self, controller_url: str, token: Optional[str], timeout: float = 5.0)` (reuse the `/api/v1/reconcile` suffix stripping from `live_state._controller_base`), `list(self) -> List[dict]`, `set(self, scenario: str, state: str, ttl_minutes: Optional[int] = None) -> dict`; both raise `ChaosError(status: int, message: str)` for HTTP errors and for an unreachable controller (status 502).
- Dashboard routes (live mode only, otherwise 409 `"Chaos controls need a live cluster"`): `GET /api/v1/chaos/scenarios`; `POST /api/v1/chaos/scenarios/{scenario_id}/start` (JSON body optional: `{ttl_minutes}`); `POST .../stop`; `POST /api/v1/chaos/stop-all`. The three POSTs use `Depends(_check_dashboard_token)`, write `add_terminal_log("WARN","CHAOS",...)` and broadcast `{"event":"CHAOS_CHANGED"}` over the WebSocket. `scenario_id` is validated against `^[a-z0-9-]{1,32}$` before any call.
- `build_state()` in live mode returns escalations from `list_open_escalations()`; demo mode keeps the dict. `resolve_escalation` also calls `resolve_escalation_record(req.incident_id)`.

- [ ] **Step 1: Write failing tests** (`test/test_dashboard_chaos.py`, FastAPI `TestClient`, patch `ChaosClient` methods and `current_data_source`): `test_chaos_routes_return_409_in_demo_mode`; `test_start_passes_scenario_and_ttl_to_the_controller`; `test_bad_scenario_id_is_rejected_before_any_call` (`"../x"`, `"A B"`, 40 chars give 422/400, client mock never called); `test_controller_unreachable_returns_502_with_message`; `test_stop_all_stops_every_running_scenario` (mock list returns 3 running, expects 3 `set(...,"off")` calls); `test_action_routes_require_dashboard_token_when_set`; `test_live_state_lists_database_escalations`; `test_resolving_an_escalation_marks_it_resolved_in_the_database`; `test_demo_mode_still_uses_the_in_memory_escalations`.
- [ ] **Step 2: Run** `PYTHONPATH=. python -m unittest discover -s test -p "test_dashboard_chaos.py"`. Expected: FAIL.
- [ ] **Step 3: Implement** `ChaosClient` and the routes; construct one `ChaosClient` next to `live_state` from the same `GO_CONTROLLER_URL` and `GO_CONTROLLER_TOKEN`. Also update the live-mode 409 message of `/api/v1/chaos/trigger` to point at the new routes.
- [ ] **Step 4: Run** the new tests and the whole suite (as Task 4 step 4). Expected: PASS.
- [ ] **Step 5: Commit** `git add src test && git commit -m "feat(dashboard): control chaos scenarios and read live escalations"`

### Task 6: Frontend chaos controls

**Files:**
- Create: `frontend/src/lib/chaos.ts`, `frontend/src/lib/chaos.test.ts`, `frontend/src/components/ChaosControls.tsx`
- Modify: `frontend/src/api/types.ts`, `frontend/src/api/client.ts`, `frontend/src/pages/Simulate.tsx`, `frontend/src/state/AegisProvider.tsx` (treat `CHAOS_CHANGED` like `PIPELINE_EVENT`), `frontend/src/styles/app.css` (only the classes the new component needs)

**Interfaces:**
- Produces in `types.ts`: `ChaosScenario { id: string; deployment: string; installed: boolean; replicas: number; ready: number; expires_at?: string }`.
- Produces in `client.ts` (`api.*`): `chaosScenarios(): Promise<{scenarios: ChaosScenario[]}>`, `chaosStart(id: string, ttlMinutes?: number)`, `chaosStop(id: string)`, `chaosStopAll()`.
- Produces in `lib/chaos.ts`: `SCENARIO_INFO: Record<string, {title: string; note: string; kind: 'operational' | 'security' | 'human'}>` (copy for all eight ids, plain words, expected outcome in `note`), `scenarioState(s: ChaosScenario): 'not-installed' | 'stopped' | 'starting' | 'running'`, `timeLeft(expiresAt: string | undefined, now: number): string | null` ("12 min left", "under 1 min left", null when absent or past).

- [ ] **Step 1: Write failing tests** in `chaos.test.ts`: `scenarioState` for each of the four cases (not installed; replicas 0; replicas 1 ready 0; replicas 1 ready 1); `timeLeft` for 12 minutes, 30 seconds, already expired, undefined, and garbage text (all but the first two give null or "under 1 min left" as named); `SCENARIO_INFO has an entry for every one of the eight ids`.
- [ ] **Step 2: Run** `cd frontend && npx vitest run`. Expected: FAIL.
- [ ] **Step 3: Implement** `lib/chaos.ts`, the api methods and types, and `ChaosControls.tsx`: a card per scenario (title, note, state, time left, Start or Stop button via `withAuth` and `toast` like `Simulate.tsx`), a **Stop all** button, polling `api.chaosScenarios()` on mount, on `state.bump` changes and every 5 seconds, and a "not installed" state with the manifest name. In `Simulate.tsx`, when `data_source === 'live'` render `ChaosControls` (page title "Chaos controls", info banner saying remediation is still dry-run); the demo branch is unchanged.
- [ ] **Step 4: Run** `cd frontend && npx vitest run && npx tsc --noEmit`. Expected: all pass, no type errors.
- [ ] **Step 5: Commit** `git add frontend && git commit -m "feat(frontend): start and stop chaos scenarios from the live console"`

### Task 7: Deploy to the AWS node and prove it live

**Files:**
- Modify: `CLAUDE.md` (chaos endpoint, `CHAOS_ENABLED`, escalations now come from the database in live mode), `PHASES.md` only if it has a chaos section that is now wrong

**Interfaces:**
- Consumes: everything above. Cluster state to set (not committed): controller env `CHAOS_ENABLED=true` via `kubectl set env`; remediation stays dry-run.

- [ ] **Step 1: Open the tunnel and port-forwards** exactly as in the earlier session (SSH tunnel on 6443, controller on 8080, Prometheus on 9090). Expected: `kubectl get nodes` shows Ready.
- [ ] **Step 2: Apply the new manifests and rebuild** `kubectl apply -f k8s/chaos/`; `PLATFORM=linux/amd64 BUILD=1 AEGIS_HOST=13.239.73.118 SSH_KEY=$HOME/.ssh/aegis.pem aws/push-image.sh controller` and the same for `brain`; `kubectl apply -f k8s/controller/controller.yaml`; `kubectl -n aegis-system set env deploy/aegis-controller CHAOS_ENABLED=true`; `kubectl -n aegis-system rollout restart deploy/aegis-brain`. Expected: both deployments roll out, `AEGIS_AUTO_REMEDIATE=true` and both dry-run flags still set.
- [ ] **Step 3: Start the live dashboard and UI** (ports 8010 and 5174, as before). Expected: `GET /api/v1/chaos/scenarios` through `:5174` lists eight scenarios, all `installed: true`, all stopped.
- [ ] **Step 4: Run each scenario once through the dashboard endpoints,** one at a time: start, wait for its incident (security scenarios within a minute; CPU/OOM/crash loop within about 3 minutes), check the diagnosis and the dry-run execution in the incidents list, stop. Expected outcomes per the design table. For `restart-storm`, expect the fourth restart decision to be refused and an item to appear on the Review list; if it does not, switch to the fallback in the design (open item 2) and tell the owner.
- [ ] **Step 5: Prove the safety rules live:** stop-all leaves everything at 0; a started scenario with `ttl_minutes: 1` stops itself within about 90 seconds; with `CHAOS_ENABLED` unset the controller answers 403.
- [ ] **Step 6: Update `CLAUDE.md`, run all suites, commit** `git add CLAUDE.md && git commit -m "docs: document chaos controls and database-backed escalations"`. Finish with every scenario at 0 replicas and the stack still dry-run.
