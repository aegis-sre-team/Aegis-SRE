# Review Fixes (Phases 1-7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (native, inline). Steps use checkbox (`- [ ]`) syntax. **No git commits until the user says so** (then: small atomic commits, single-line messages, no co-author trailer).

**Goal:** Fix every defect found by the `/code-review` pass (9 findings on the Phase 5-7 work) and by a manual audit of Phases 1-4 (sensors, brain, guardrails), each with a test that fails first.

**Architecture:** Same components as before; this plan only hardens them. Themes: (1) the brain must never over-trust its inputs (LLM output, Falco/AlertManager payloads, untrusted pod logs); (2) numbers and results must be honest (no-data is not "normal", dry-run is not "verified", a dry-run controller is not "healed"); (3) safety limits must key on what actually restarts (the workload) and be race-free; (4) evidence must never be overwritten.

**Tech Stack:** Python 3.12 (FastAPI, unittest), Go 1.27 (client-go fakes), Prometheus/Falco YAML.

**Spec:** `PHASES.md` (Phases 1-7 success criteria), `docs/superpowers/plans/2026-11-17-phases-5-7-completion.md`, and the findings table below.

## Findings driving this plan

| ID | Source | Finding | Task |
|---|---|---|---|
| R1 | review | controller reply `mode=dry_run` treated as a real action; verification can then report "healed" | 5 |
| R2 | review | Go `restart` deletes bare/uncontrolled pods (permanent loss) | 5 |
| R3 | review | dashboard HITL never sends `namespace`; JS ignores non-2xx | 6 |
| R4 | review | auto-remediate runs synchronously in the AlertManager webhook (timeouts, duplicate actions); no webhook debounce | 4 |
| R5 | review | `/alerts/falco` trusts body, no auth, pod name goes into file paths | 4 |
| R6 | review | a second quarantine overwrites the first forensics snapshot | 5 |
| R7 | review | restart cap keyed by pod name, defeated by rollout (new names) | 1 |
| R8 | review | dry-run reports `verified: true` | 4 |
| R9 | review | `AlertDebouncer` not thread-safe, unbounded, records before success | 4 |
| R10 | review | HITL path skips namespace policy | 6 |
| B1 | audit | PromQL/LogQL built by string interpolation, substring match across pods/namespaces (wrong evidence, injection) | 2 |
| B2 | audit | missing metric shown as `0.0% NORMAL` (no-data looks healthy) | 2 |
| B3 | audit | untrusted logs/Falco text goes into the LLM prompt; an attacker can talk the model out of quarantine | 3 |
| B4 | audit | missing confidence silently becomes 0.85 and passes the 0.70 gate; out-of-range accepted | 1 |
| G2 | audit | `UNQUARANTINE_POD` can be approved autonomously (releases an attacker) | 1 |
| S1 | audit | only a CPU alert rule exists; OOM and crash-loop chaos can never reach the brain | 7 |
| S2 | audit | Falco "sensitive file" rule fires on `/etc/passwd` reads (normal) => autonomous quarantine of healthy pods | 7 |
| S3 | audit | cAdvisor scrape sets `insecure_skip_verify: true` while a CA file is configured | 7 |
| S4 | audit | Falco events from unmanaged/protected namespaces trigger LLM calls and escalation spam | 4 |

## Global Constraints

- Allowed actions, protected namespaces and quarantine label design are unchanged.
- Workload restart-budget key: `"<namespace or '-'>/<workload>"`, workload = pod name minus ReplicaSet hash + pod suffix (`^(.+)-[a-z0-9]{8,10}-[a-z0-9]{5}$`), or minus StatefulSet ordinal (`^(.+)-\d+$`), else the pod name.
- A verdict with missing, non-numeric, or out-of-[0,1] `confidence` is invalid (escalate); never defaulted upward.
- Kubernetes names accepted from outside the process must match DNS-1123 (`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`, max 253).
- `AEGIS_INGEST_TOKEN` (optional): when set, `/api/v1/alerts/webhook` and `/api/v1/alerts/falco` require `X-Aegis-Token: <token>` or `Authorization: Bearer <token>`.
- No new Python dependencies. No commits.

## Review Focus

1. A pod name containing PromQL/regex metacharacters (quotes, `.`, `|`) -> exact, escaped match; never another pod's data.
2. A verdict with no/garbage/out-of-range `confidence` -> escalated, never auto-approved.
3. LLM output contradicting a trusted Falco alert (says "OPERATIONAL_BUG/RESTART") -> quarantine still wins.
4. Alerts for replacement pods of the same Deployment -> one shared restart budget (concurrent requests included).
5. Brain live but controller in `DRY_RUN` -> reported as a failure and escalated, never "healed".
6. Forged/out-of-scope Falco events (bad name, protected namespace) -> ignored without an LLM call.

## File Structure

- `src/guardrails/action_schema.py`, `validator.py`: `workload_key`, public `namespace_violation`, confidence rules, UNQUARANTINE rule, locked restart accounting.
- `src/brain/collector.py`, `metric_serializer.py`: scoped/escaped queries, no-data honesty.
- `src/brain/prompt_templates.py`, `diagnostic_engine.py`, `llm_client.py`: untrusted-evidence rule, trusted-Falco override, confidence default 0.
- `src/brain/remediation.py`, `main.py`: debouncer, validation, token, background auto-remediation, `verified` semantics.
- `src/controller/executor.py`, `controller/workload.go`, `controller/quarantine.go`: dry-run mismatch, forensics never overwritten, safe restart, already-quarantined no-op.
- `src/dashboard/server.py`, `static/app.js`: HITL namespace + policy + error handling.
- `k8s/monitoring/prometheus.yaml`, `falco.yaml`, `config/falco/falco_rules.local.yaml`: new alert rules, narrower Falco rule, TLS verify.
- Tests: new `test/test_collector.py`, `test_hardening.py`; extend existing modules named per task.

---

### Task 1: Guardrail hardening (R7, B4, G2, R10 helper)

**Files:** Modify `src/guardrails/action_schema.py`, `src/guardrails/validator.py`, `src/brain/llm_client.py`, `src/brain/diagnostic_engine.py`; Test `test/test_guardrails.py`.

**Interfaces:**
- Produces: `workload_key(namespace: Optional[str], pod_name: str) -> str` (action_schema); `GuardrailEngine.namespace_violation(namespace: Optional[str], action: str) -> Optional[str]` (public staticmethod; `_namespace_violation` kept as alias); `GuardrailEngine._check_and_record_restart(pod_name, namespace=None)` keyed by `workload_key` under `self._restart_lock` (threading.Lock).

- [ ] Step 1: Failing tests: `test_workload_key_strips_replicaset_and_statefulset_suffixes` (`("online-boutique","cartservice-6f7d8c9b5-x2k4p") -> "online-boutique/cartservice"`, `("db","redis-0") -> "db/redis"`, `(None,"lonely") -> "-/lonely"`); `test_restart_budget_is_shared_across_replacement_pods` (4 restarts for 4 different pod names of one Deployment: 3 approved, 4th `rate_limit_exceeded`); `test_restart_budget_not_shared_across_namespaces`; `test_restart_budget_holds_under_concurrency` (20 threads, limit 3 -> exactly 3 approved); `test_missing_confidence_is_escalated` / `test_out_of_range_confidence_is_rejected` (1.5, -0.1, "high") -> not approved, `schema_valid False` for garbage, escalate; `test_autonomous_unquarantine_is_escalated` (state `STATE_ACTION_REJECTED`, reason mentions "human"); `test_namespace_violation_is_public`.
- [ ] Step 2: Run `python -m unittest discover -s test -p "test_guardrails.py"`; expect the new tests to fail.
- [ ] Step 3: Implement. Confidence: `LLMVerdictSchema.confidence` default 0.0, `_coerce_confidence` -> 0.0 for None/"" and raises ValueError for non-numeric/outside [0,1]. UNQUARANTINE rule goes after the allowlist check (message: "Releasing a quarantine requires a human operator"). Remove `setdefault("confidence", 0.85)` in `llm_client.py` and `diagnostic_engine.py` (use 0.0). Pass `namespace` into `_check_and_record_restart` from `_evaluate_policy`.
- [ ] Step 4: Full suite; fix any existing test that relied on the 0.85 default by making its confidence explicit.

### Task 2: Scoped, escaped telemetry queries; no-data honesty (B1, B2)

**Files:** Modify `src/brain/collector.py`, `src/brain/metric_serializer.py`, `src/brain/diagnostic_engine.py` (pass namespace); Test `test/test_collector.py` (new).

**Interfaces:**
- Produces: `escape_label_value(s: str) -> str` (backslash + double-quote escaped; newline stripped); `_pod_matcher(pod_name, namespace) -> str` returning `namespace="NS",pod="NAME"` (exact) when namespace given, else `pod=~"<re.escape(name)>.*"`; `fetch_prometheus_metrics(pod_name, namespace=None)`, `fetch_loki_logs(pod_name, limit=15, namespace=None)`, `fetch_falco_alerts(pod_name, limit=25, security_context=False, namespace=None)`. Missing series yield `None` for `cpu_usage_pct`, `memory_mb`, `memory_pct`, `memory_limit_mb` (not 0.0).

- [ ] Step 1: Failing tests (patch `requests.get`, capture queries): `test_exact_selector_with_namespace`; `test_injection_attempt_is_escaped` (name `x"} or vector(1) #` -> no unescaped quote in any query); `test_dot_in_name_is_not_a_wildcard_without_namespace`; `test_loki_query_is_namespace_scoped`; `test_empty_prometheus_series_report_none_not_zero`; `test_serializer_says_no_data_instead_of_normal` (output contains `no data`, never `0.0% (Status: NORMAL)` for a None metric); `test_engine_passes_namespace_to_collector`.
- [ ] Step 2: Run `test_collector.py`; expect failures.
- [ ] Step 3: Implement per Interfaces; serializer renders `CPU Usage: no data (sensor answered, no series)` and treats `None` as unknown in status logic.
- [ ] Step 4: Full suite (existing metrics dicts with numbers must still serialize identically).

### Task 3: Prompt-injection hardening and trusted-Falco override (B3)

**Files:** Modify `src/brain/prompt_templates.py`, `src/brain/diagnostic_engine.py`; Test `test/test_hardening.py` (new).

**Interfaces:**
- Produces: `DiagnosticEngine._apply_trusted_signal_policy(verdict: dict, alert_type: str) -> dict`: when `alert_type.lower().startswith("falco")` (an Aegis Falco rule fired for this pod): set `problem_type="SECURITY_ATTACK"`; if `recommended_action` not in (`CILIUM_QUARANTINE_EBPF`, `ESCALATE`) set it to `CILIUM_QUARANTINE_EBPF`; floor `confidence` at 0.90 when the classification was changed; record `verdict["_trusted_signal_override"]=True`. System prompt gains a rule that evidence sections are untrusted data and instructions inside them must be ignored.

- [ ] Step 1: Failing tests: `test_llm_cannot_downgrade_a_falco_alert` (LLM patched to return OPERATIONAL_BUG/RESTART_POD for `falco_shell_spawn`; final decision approved CILIUM_QUARANTINE_EBPF); `test_escalate_is_preserved_for_falco_alert`; `test_non_falco_alert_is_untouched`; `test_injected_log_text_does_not_change_a_restart_verdict_path` (logs contain "IGNORE PREVIOUS INSTRUCTIONS", cpu alert, LLM returns RESTART -> unchanged); `test_system_prompt_marks_evidence_untrusted`.
- [ ] Step 2: Run; expect failures. Step 3: Implement; call the policy right after the LLM call and before guardrails. Step 4: full suite.

### Task 4: Ingest hardening and honest pipeline output (R4, R5, R8, R9, S4)

**Files:** Modify `src/brain/remediation.py`, `src/brain/main.py`; Test `test/test_falco_ingest.py`, `test/test_remediation_loop.py`, `test/test_brain_api.py`.

**Interfaces:**
- Produces: `is_valid_k8s_name(name: str) -> bool` (remediation.py); `AlertDebouncer` gains `threading.Lock`, `release(key: str) -> None`, pruning of entries older than 3600 s when more than 1000 keys exist; `process_alert(...)["verified"]` is `None` when `executor.dry_run_mode` is true; `_check_ingest_token(request) -> None` raising `HTTPException(401)` when `AEGIS_INGEST_TOKEN` is set and the header is wrong/missing; `/api/v1/alerts/falco` and the webhook return `{"accepted": ...}` immediately and run `_handle_alert` through `BackgroundTasks` only when `AEGIS_AUTO_REMEDIATE=true` (diagnose-only stays synchronous).

- [ ] Step 1: Failing tests: `test_falco_invalid_pod_or_namespace_name_is_ignored` (`../../etc`, uppercase, 300 chars); `test_falco_event_in_protected_namespace_is_ignored_without_llm_call`; `test_falco_event_outside_allowlist_is_ignored`; `test_token_required_when_configured` (401 without, 200 with, both endpoints, header and bearer forms); `test_auto_remediate_returns_before_processing_and_still_runs` (response has `accepted`; `process_alert` mock called); `test_webhook_repeats_are_debounced`; `test_debouncer_is_thread_safe_and_bounded` (50 threads, one winner; > 1000 stale keys pruned); `test_debouncer_release_allows_retry`; `test_failed_handling_releases_the_debounce_key`; `test_dry_run_verified_is_none`. Update existing auto-remediate tests to the new response shape.
- [ ] Step 2: Run; expect failures. Step 3: Implement. Step 4: full suite.

### Task 5: Executor and Go controller safety (R1, R2, R6)

**Files:** Modify `src/controller/executor.py`, `controller/workload.go`, `controller/quarantine.go`; Test `test/test_executor_controller.py`, `controller/workload_test.go`, `controller/quarantine_test.go`.

**Interfaces:**
- Produces: executor status code `FAILED_CONTROLLER_DRY_RUN` when the controller answers `mode == "dry_run"` while the brain is live (no DB record, no forensics file, `success False`); `_persist_controller_forensics` never overwrites: first snapshot -> `forensics_<pod>.json`; later snapshots -> `forensics_<pod>_<UTC yyyymmddThhmmssZ>.json`; a missing snapshot with an existing base returns the base path unchanged. Go: `restart` deletes a pod only when it has a controller owner of kind `ReplicaSet`, `StatefulSet` or `DaemonSet`; otherwise `ErrNoWorkload` (HTTP 422). Go `quarantine` returns `status "success"`, message containing `already quarantined`, `Forensics == nil`, policy untouched, when the pod already has the label AND the policy exists.

- [ ] Step 1: Failing tests (Python): `test_controller_dry_run_reply_is_a_failure_when_brain_is_live`; `test_second_quarantine_does_not_overwrite_first_forensics`; `test_missing_forensics_does_not_clobber_existing_file`. (Go): `TestRestartBarePodIsRefused` (replaces `TestRestartBarePodDeletesIt`), `TestRestartStatefulSetPodDeletesIt`, `TestRestartJobOwnedPodIsRefused`, `TestSecondQuarantineIsANoOp` (assert no policy update action recorded, `Forensics == nil`).
- [ ] Step 2: Run `go test` and the Python module; expect failures. Step 3: Implement. Step 4: `go vet ./... && go test ./...`, full Python suite.

### Task 6: Dashboard HITL correctness (R3, R10)

**Files:** Modify `src/dashboard/server.py`, `src/dashboard/static/app.js`; Test `test/test_live_state.py`.

**Interfaces:** `/api/v1/escalation/resolve` returns 400 when the data source is live and `namespace` is empty; 403 (detail = the violation text) when `GuardrailEngine.namespace_violation(namespace, action)` is non-empty; demo mode keeps accepting a missing namespace. JS sends `namespace` (looked up from the last rendered pods by name) and, on a non-2xx response, logs an ERROR with the server `detail` and keeps the drawer open.

- [ ] Step 1: Failing tests: `test_hitl_live_requires_namespace`; `test_hitl_protected_namespace_is_forbidden`; `test_hitl_allowlist_is_enforced`; `test_hitl_demo_without_namespace_still_works`.
- [ ] Step 2: Run; expect failures. Step 3: Implement server + JS (`let lastPods = []` set in `renderPodCards`); `node --check app.js`. Step 4: full suite.

### Task 7: Sensor manifests (S1, S2, S3)

**Files:** Modify `k8s/monitoring/prometheus.yaml`, `k8s/monitoring/falco.yaml`, `config/falco/falco_rules.local.yaml`, `src/brain/main.py` (`_alert_type_from_labels`), `src/brain/llm_client.py` (rule fallback for crash loops); Test `test/test_manifests.py`, `test/test_brain_api.py`.

**Interfaces:** new rules in a second rules key `aegis-health.yml` of ConfigMap `prometheus-rules`: `AegisContainerOOMKilled` (`sum by (namespace,pod)(increase(container_oom_events_total{namespace=~"online-boutique|aegis-chaos"}[5m])) > 0`, `for: 0m`) and `AegisPodCrashLooping` (`sum by (namespace,pod)(changes(container_start_time_seconds{container!="",container!="POD",namespace=~"online-boutique|aegis-chaos"}[10m])) >= 3`, `for: 1m`), both labelled `severity: warning`, `aegis_path: bug`, with `summary` annotations. Alert-name mapping: `OOMKilled` -> `OOM_KILLED_RISK` (existing), `CrashLooping` -> `CRASHLOOP_BACKOFF` (new; rule fallback returns `RESTART_POD`, confidence 0.80, so the per-workload cap escalates after 3). `Aegis Sensitive File Read` matches `/etc/shadow` and `/etc/sudoers` only. The cadvisor scrape loses `insecure_skip_verify`.

- [ ] Step 1: Failing tests: `test_prometheus_has_oom_and_crashloop_rules_routable_by_alertmanager` (names, `severity: warning`, namespace matcher); `test_sensitive_file_rule_ignores_etc_passwd` (both rule files); `test_cadvisor_scrape_verifies_tls`; `test_crashloop_and_oom_alert_names_map_to_alert_types`; `test_crashloop_fallback_is_a_bounded_restart`.
- [ ] Step 2: Run; expect failures. Step 3: Implement. Step 4: full suite; note in `k8s/PHASE2_VERIFY.md` that cadvisor TLS and the new rules need a live check.

### Task 8: Docs, verification, re-review

- [ ] Step 1: Update `CLAUDE.md` (new env `AEGIS_INGEST_TOKEN`, workload restart budget, trusted Falco override, ingest scope), `k8s/PHASE6_VERIFY.md` (OOM/crash-loop drills, token enablement, ingest ignore cases), `k8s/PHASE2_VERIFY.md`.
- [ ] Step 2: Final run: Python suite twice, `go vet ./... && go test -count=1 ./...`, `bash -n aws/*.sh`, parse every `k8s/**/*.yaml`, `node --check` on `app.js`. Expected: all green.
- [ ] Step 3: Write `docs/superpowers/plans/2026-11-17-review-fixes-phases-1-7.execution.md` (results, rulings, what is still unverified live). Do not commit.

## Self-review

- Coverage: every ID in the findings table maps to a task; Review Focus 1->T2, 2->T1, 3->T3, 4->T1, 5->T5, 6->T4.
- Type consistency: `namespace_violation` (T1) is consumed by T4 and T6; `workload_key` (T1) is used only inside the validator; `is_valid_k8s_name` (T4) is local to the brain; the forensics file naming (T5) keeps the base name the dashboard reads.
- Honest limits: Falco `http_output` authentication cannot use the token header without a live check (the Falco config cannot read a secret); the token therefore stays optional and documented, not enabled by default.

---

### Task 9: Second review round (findings R2-1 .. R2-9)

A second `/code-review` pass over the fixes found nine more issues; all were verified valid and fixed test-first (`test/test_review_round2.py`, Go tests, `test_live_state.py`).

| ID | Finding | Fix |
|---|---|---|
| R2-1 | `/api/v1/controller/execute` router unguarded and self-approving | ingest token on the router; DNS-1123 name check; namespace policy (403) |
| R2-2 | dashboard `escalation/resolve` and chaos trigger unauthenticated though they now run real actions | optional `AEGIS_DASHBOARD_TOKEN` on both POST endpoints; UI sends/prompts for it |
| R2-3 | `/diagnose` and `/remediate` accept unvalidated pod/namespace/alert_type (file paths, kubectl args, queries) | pydantic validators (DNS-1123 names, `^[A-Za-z0-9_.:-]{1,64}$` alert types) -> 422 |
| R2-4 | missing namespace silently becomes `default` for live actions | live executor refuses (`FAILED_NO_NAMESPACE`) |
| R2-5 | verification passes while the old StatefulSet/bare pod is still terminating | controller reports `terminating`; verification requires `not terminating` |
| R2-6 | Python workload resolution assumes ReplicaSet naming (StatefulSet `my-db-0` -> `my`) | owner kind aware `kind/name` ref for kubectl fallback |
| R2-7 | dry-run results say "Health Verification: PASSED" and write `health_verified=True` to the audit trail | dry-run results report `health_verified: null` + `dry_run: true`; text corrected |
| R2-8 | Go `scale` accepts `replicas <= 0` | `ErrInvalidReplicas` (HTTP 400) before any cluster call |
| R2-9 | quarantine DB rows keyed by pod name only; dry-run writes active rows that the dashboard restores as real | rows scoped by (pod, namespace); dry-run records nothing |
| R2-10 | dashboard live CPU/memory keyed by pod name and unescaped namespace regex | `sum by (namespace, pod)`, `(namespace, pod)` keys, escaped selector |
