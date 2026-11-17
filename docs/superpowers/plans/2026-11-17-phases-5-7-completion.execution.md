# Execution record: Phases 5-7 completion

Plan: `2026-11-17-phases-5-7-completion.md`. Executed inline (native), no commits made (user rule: commit only when told).
Final state: **138 Python tests pass (run repeatedly, ~8-10 s; baseline was 35 tests with 7 failing in ~170 s), 41 Go tests pass, `go vet` clean, linux/arm64 static cross-compile OK, `bash -n` on all `aws/*.sh`, 19 `k8s/**/*.yaml` files parse, `node --check` on `app.js`.**

## Task results

| Task | Result |
|---|---|
| 1 Test isolation | `test/support.py` (temp DB, no cloud LLM, `DASHBOARD_MODE=demo`, `sensor_patches`, restart-state reset). Fixed all 7 baseline failures (cause: fail-closed engine vs unmocked sensors; shared DB leaking restart counters). Corrected the single-test command in CLAUDE.md. |
| 2 Namespace guardrails | `namespace` through schema/decision/engine/webhook/API; `PROTECTED_NAMESPACES`; optional `AEGIS_ALLOWED_NAMESPACES` (fail-closed); LLM cannot set the namespace. |
| 3 Cilium policy (Python) | Label selector + `ingressDeny`/`egressDeny`; `quarantine_label_value` vector shared with Go. |
| 4 Go core | types/safety/workload/reconciler; owner-reference restart, capped scale, dry-run mutates nothing. |
| 5 Go quarantine/forensics/server | forensics-first quarantine, idempotent, status + pods APIs, bearer auth, SPDY exec, env-configured `main`. |
| 6 Packaging | Dockerfile, namespaced-Role RBAC manifests, brain wiring, `aws/` image + token steps, `PHASE5_VERIFY.md`, `test_manifests.py`. |
| 7 Python executor | controller-first, fail-closed, token + namespace, real forensics only, DB record, opt-in kubectl fallback. |
| 8 Phase 6 loop | `process_alert`, honest verification (generation + replica checks), Falco ingest + debounce + Falco `http_output`, `PHASE6_VERIFY.md`. Two mutation checks proved the tests catch regressions. |
| 9 Phase 7 dashboard | live/demo modes with `data_source`, honest pills + startup log, real forensics (404 when none), HITL through executor, pipeline events, UI null handling, `PHASE7_VERIFY.md`. |
| 10 Docs + verification | PHASES.md, CLAUDE.md, README status notes; final-review fixes below. |

## Rulings made (decisions taken without asking)

1. No worktree and no commits (user rule). Final review is a self-review (user chose the native method); a fresh reviewer would be stronger.
2. `test.test_x` single-test command does not work (stdlib `test` shadows it); documented `discover -s test -k` instead.
3. Added `test_isolation.py` and DB-reset helpers beyond the plan (in-run pollution between test modules).
4. Engine overwrites `verdict["namespace"]` from the alert: LLM output is untrusted.
5. Go restart/scale use Deployment Get+Update, not the scale subresource (fake clientset subresource support unreliable); RBAC therefore needs `deployments update` (slightly broader than `deployments/scale`).
6. Namespaced Roles for `online-boutique` and `aegis-chaos` instead of the plan's ClusterRole (stronger least privilege). A new managed namespace needs a new Role + `ALLOWED_NAMESPACES` entry.
7. Added `workload` to the controller result so verification can follow the Deployment after the old pod is gone (plan gap).
8. Added a Falco ingest endpoint and enabled Falco `http_output` (plan gap: nothing connected Falco events to the brain; AlertManager only sees Prometheus). Added `ns=%k8s.ns.name` to the Aegis Falco rules so events name the namespace.
9. Alert endpoints changed from `async def` to `def` (blocking LLM/verification calls must not freeze the event loop and the health probe).
10. Dry-run verification returns True (nothing to verify); `process_alert` now reports `dry_run` so that is not mistaken for a real heal.
11. Unapproved decisions are never sent to the executor (no cluster path at all).
12. `ESCALATE` never goes through the controller (found in self-review).
13. Kept the legacy `simulated_process_tree` key in forensics (now real data) because the UI reads it; the UI now prefers `process_tree`.
14. Dashboard `DASHBOARD_MODE=auto` is live only when the controller answers; explicit `live` never silently shows demo data.
15. Go RED was not observed for Task 4 (first `go mod tidy` hung ~10 min); tests were written before the code.

## Not verified (cannot be, offline)

- Controller image build (Docker daemon was not running; only the linux/arm64 static cross-compile was proven).
- RBAC sufficiency, Cilium accepting/enforcing the deny policy, SPDY exec, Falco `http_output` delivery, K3s v1.30 + Cilium 1.16 install on AWS, every `aws/*.sh` script against real AWS.
- The dashboard UI in a browser.

## Deferred minors / known limits

- `/api/v1/alerts/falco` and `/api/v1/alerts/webhook` are unauthenticated inside the cluster; with `AEGIS_AUTO_REMEDIATE=true` a compromised pod could forge events to quarantine other pods in the managed namespaces (bounded by guardrails, namespaces and the replica cap). Hardening: shared-secret header (Falco supports `http_output.custom_headers`) and a NetworkPolicy on the brain.
- `forensics`/`telemetry` handlers in the dashboard still make a few blocking HTTP calls on the event loop (cached, short timeouts; the demo-mode Prometheus poll is pre-existing).
- Audit table has no namespace column, so `PIPELINE_EVENT` rows do not show it.
- `test/` still contains the older hands-on lab under `test/app`, `test/k8s` etc. that was not touched.
