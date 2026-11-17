# Execution record: review fixes (Phases 1-7)

Plan: `2026-11-17-review-fixes-phases-1-7.md`. Executed inline (native). **No commits made** (user rule). Every fix was written test-first and watched failing before the fix.

State after the fixes: **194 Python tests pass (run twice, ~12 s), 45 Go tests pass, `gofmt` clean, `go vet` clean, linux/arm64 static build OK, `bash -n` on all `aws/*.sh`, 22 YAML files parse, `node --check app.js`.** (Before: 138 Python / 41 Go.)

## What was wrong and is now fixed

| ID | Finding | Fix | Proving test (file) |
|---|---|---|---|
| R7 | restart cap keyed by pod name, defeated by rollouts (each restart renames the pod) | key = namespace/workload (`workload_key`), atomic under a lock | `test_restart_budget_is_shared_across_replacement_pods`, `..._holds_under_concurrency` (test_guardrails) |
| B4 | missing confidence became 0.85 and passed the 0.70 gate; out-of-range accepted | missing = 0.0 (escalate); non-numeric/out-of-[0,1] = invalid verdict | `test_missing_confidence_is_escalated...`, `test_garbage_or_out_of_range_confidence_is_rejected` |
| G2 | `UNQUARANTINE_POD` approvable autonomously (releases an attacker) | rejected with "requires a human operator" | `test_autonomous_unquarantine_is_escalated_to_a_human` |
| B1 | PromQL/LogQL built by string interpolation + substring match across pods/namespaces | namespace + exact pod, escaped | `test_exact_selector_with_namespace`, `test_injection_attempt_is_escaped`, ... (test_collector) |
| B2 | missing metric rendered as `0.0% NORMAL` | `None` -> "no data" | `test_empty_prometheus_series_report_none_not_zero`, `test_serializer_says_no_data...` |
| B3 | untrusted logs/Falco text in the LLM prompt could talk the model out of a quarantine | prompt marks evidence untrusted; a trusted Falco alert forces SECURITY_ATTACK/quarantine | `test_llm_cannot_downgrade_a_falco_alert`, ... (test_hardening) |
| R1 | controller answering `mode: dry_run` treated as a real action (could report "healed") | `FAILED_CONTROLLER_DRY_RUN`, no DB record, no verification | `test_controller_dry_run_reply_is_a_failure_when_the_brain_is_live` |
| R2 | Go `restart` deleted bare/Job pods (permanent loss) | only ReplicaSet/StatefulSet/DaemonSet-controlled pods; else HTTP 422 | `TestRestartBarePodIsRefused`, `TestRestartJobOwnedPodIsRefused` |
| R6 | a second quarantine overwrote the first (pre-isolation) forensics | Go: already-quarantined is a no-op; Python: real snapshots never overwritten | `TestSecondQuarantineIsANoOp...`, `test_second_quarantine_does_not_overwrite_the_first_forensics` |
| R3 | dashboard HITL never sent a namespace; UI ignored non-2xx | namespace sent; errors shown, drawer kept open | `test_hitl_live_requires_a_namespace` (+ JS) |
| R10 | HITL skipped the namespace policy | same `namespace_violation` as autonomous actions (403) | `test_hitl_protected_namespace_is_forbidden_in_any_mode`, `..._allowlist_is_enforced` |
| R4 | auto-remediation ran inside the AlertManager webhook (timeouts -> duplicate actions), no debounce | background task, immediate `accepted`, debounced | `test_webhook_returns_accepted...`, `test_webhook_repeats_are_debounced...` (test_ingest_hardening) |
| R5 | `/alerts/falco` trusted its body, no auth, names reached file paths | DNS-1123 validation, managed-namespace scope, optional `AEGIS_INGEST_TOKEN` on all action endpoints | `TestNameValidation`, `TestFalcoScope`, `TestIngestToken` |
| R8 | dry-run reported `verified: true` | `None` in dry-run | `test_result_reports_whether_the_run_was_dry` |
| R9 | debouncer not thread-safe, unbounded, claimed before success | lock, pruning, `release` on failure | `TestDebouncer`, `test_failed_handling_releases_the_debounce_key...` |
| S1 | only a CPU alert rule existed; OOM / crash-loop chaos could never reach the brain | `AegisContainerOOMKilled`, `AegisPodCrashLooping` + alert-type mapping + bounded fallback | `TestSensorManifests`, `TestAlertTypeMapping` |
| S2 | Falco "sensitive file" rule fired on `/etc/passwd` (normal) -> autonomous quarantine of healthy pods | `/etc/shadow` + `/etc/sudoers` only | `test_sensitive_file_rule_ignores_etc_passwd` |
| S3 | cAdvisor scrape skipped TLS verification | removed `insecure_skip_verify` | `test_cadvisor_scrape_verifies_tls` |
| S4 | Falco events from unmanaged namespaces caused LLM calls / escalation spam | ignored before any work | `test_protected_namespace_is_ignored_without_an_llm_call` |

Found while fixing (not in the review): `_alert_type_from_labels` classified any alert whose summary contained "shell" (e.g. a pod named `chaos-shell-injection-...`) as a Falco security alert; with the new trusted-Falco override that would have forced a quarantine. Now decided from the rule name/path only (`test_a_pod_named_shell_does_not_turn_a_bug_alert_into_a_security_alert`).

## Rulings made without asking

1. The forensics "never overwrite" rule applies only to REAL (cluster) snapshots; dry-run/empty files may still be replaced (otherwise a demo run would block a later real capture). Later real captures go to `forensics_<pod>_<UTC timestamp with microseconds>.json` (the plan said seconds; microseconds avoid collisions).
2. `AEGIS_INGEST_TOKEN` is optional and off by default, and is NOT enabled in the manifests: Falco `http_output` cannot be shown to support a custom header from here. Enabling it needs both senders configured (steps in `k8s/PHASE6_VERIFY.md`). Until then the in-cluster endpoints remain unauthenticated; name validation, namespace scope, debouncing and the guardrails still bound what a forged event can do.
3. Alerts for namespaces outside the managed set are only filtered for Falco events (ignored). AlertManager alerts come from our own rules (which already match only `online-boutique|aegis-chaos`), so the webhook does not filter by namespace; the guardrails still reject protected/unmanaged ones.
4. The crash-loop fallback restarts once (confidence 0.80) and relies on the per-workload budget to escalate, instead of escalating immediately; this matches the existing "crash-loop rate limiter" benchmark semantics.
5. HITL in demo mode still accepts a missing namespace (the demo store has none); live mode requires one.
6. Restart-event rows now store the workload key in the existing `target_pod` column (`String(128)`); keys longer than 120 chars are truncated + hashed rather than altering the schema of the live Neon table.

## Still not verified (cannot be offline)

Everything listed in `2026-11-17-phases-5-7-completion.execution.md` (image build, RBAC, Cilium enforcement, Falco delivery, AWS scripts, browser UI), plus: the new Prometheus rules firing on real OOM/crash-loop chaos, cAdvisor scraping with TLS verification on K3s, and Falco's behavior with the narrowed rule. All have checklist items in `k8s/PHASE2_VERIFY.md` / `PHASE5_VERIFY.md` / `PHASE6_VERIFY.md`.

## Deferred minors / known limits

- Phase 1 (chaos/Boutique manifests) and Loki/Promtail configs were only read, not changed; no defects found that warranted a change without a live cluster.
- Cloud LLM fallbacks (Groq/Gemini) send evidence (logs, pod names) to a third party; unchanged, document before use with sensitive workloads.
- `chaos-http-500` has no detection path (Boutique exposes no HTTP error metrics and there is no Loki ruler); it is a load generator only.
- The dashboard still makes a few short, cached blocking HTTP calls on its event loop, and its demo-mode Prometheus poll is pre-existing.
- The audit table has no namespace column.

---

## Round 2 (second `/code-review` pass over the fixes)

The second review found 9 more issues; all were verified valid and fixed test-first (215 Python tests, 48 Go tests afterwards). Details in Task 9 of the plan.

| ID | Fix | Proving test |
|---|---|---|
| R2-1 | `/api/v1/controller/*` router behind the ingest token; names validated; namespace policy (403) | `TestControllerRouterIsGuarded` |
| R2-2 | optional `AEGIS_DASHBOARD_TOKEN` on chaos + HITL POSTs; UI `authFetch` | `TestDashboardToken` |
| R2-3 | `IncidentRequest` validators (names, alert type) -> 422 | `TestIncidentRequestValidation` |
| R2-4 | live executor refuses a decision with no namespace | `TestLiveNeedsAnExplicitNamespace` |
| R2-5 | `terminating` in `/status`; verification ignores a terminating pod | `TestStatusReportsATerminatingPod` (Go), `TestTerminatingPodIsNotHealthy` |
| R2-6 | owner-kind aware workload ref for the kubectl fallback | `TestWorkloadKindAwareFallback` |
| R2-7 | dry-run results: `dry_run: true`, `health_verified: null`, honest text, honest audit | `TestDryRunDoesNotClaimVerification` |
| R2-8 | Go rejects `replicas < 1` (400) before any cluster call | `TestValidateRejectsNonPositiveReplicas`, `TestServerRejectsNonPositiveReplicasBeforeTouchingTheCluster` |
| R2-9 | quarantine rows scoped `"<ns>/<pod>"`; dry-run records nothing | `TestQuarantineRecordScope` |
| R2-10 | live dashboard metrics keyed `(namespace, pod)`; selector escaped | `test_same_pod_name_in_two_namespaces_is_not_merged`, `test_prometheus_queries_group_by_namespace_and_escape_the_selector` |

Rulings in this round:

1. Quarantine rows keep the existing unique `target_pod` column and store `"<namespace>/<pod>"` there. Reason: the live (Neon) table already has the unique constraint and cannot be migrated from here. Older rows that hold a bare pod name are still read by the dashboard restore (it splits on `/`). Cost if wrong: old rows are never matched by the new key, so a pod quarantined by the old code is not recognised as quarantined by an unquarantine; it still works through the controller.
2. `AEGIS_DASHBOARD_TOKEN` is optional and off by default (like the ingest token) to avoid breaking the open demo flow; with it unset the HITL endpoint remains unauthenticated, which is why the verify doc and CLAUDE.md say to set it before exposing port 8000.
3. `ActionExecutionResult.health_verified` (the attribute) is left as-is for in-process callers (`process_alert` relies on it); only the serialised/audited value is `null` for dry runs.
4. The HITL drawer sends the namespace of the pod as last rendered by the grid; if the grid does not know the pod, live mode answers 400 rather than guessing.

---

## Round 3 (third `/code-review` pass over the round-2 fixes)

Nine findings; seven were real and are fixed test-first (232 Python tests, 49 Go tests afterwards); two were deliberately not changed; one is bookkeeping.

| Finding | Verdict | Fix / reason | Test |
|---|---|---|---|
| restart budget spent at validation time, so diagnose-only calls could exhaust it | real | `validate_verdict(..., reserve_budget=False)` peeks; only acting paths (`process_alert`, executor-bound decisions) spend it; `/diagnose` and diagnose-only webhooks peek | `TestRestartBudgetIsSpentOnlyWhenActing` |
| trusted-Falco override fired on a caller-typed `alert_type` | real | override requires `trusted_signal=True`; set only by Falco ingest, AlertManager ingest and the demo simulator | `TestTrustedSignalNeedsATrustedSource` |
| unquarantine marked the DB inactive before the delete succeeded | real | record only after success | `TestUnquarantineRecordFollowsTheOutcome` |
| Falco namespace filter used substring matching (`ns=prod` vs `ns=production`, `sessions=`) | real | token-boundary regex | `TestFalcoNamespaceMatchingIsExact` |
| kubectl SCALE fallback hard-coded `replicas=2` (could scale DOWN) | real | +1, capped at `MAX_REPLICAS`, never down | `TestScaleFallbackMatchesTheController` |
| verification used kubectl whenever the fallback flag was set, even for controller actions; quarantine verification always True | real | controller actions verify via the controller; kubectl quarantine/release checks the policy | `TestVerificationFollowsWhoActed` |
| Go bearer check accepted a bare token | real | `strings.CutPrefix`, scheme required | `TestServerRequiresTheBearerSchemeNotJustTheToken` |
| endpoints unauthenticated unless `AEGIS_INGEST_TOKEN` is set (manifest does not set it) | **not changed** | known and documented: Falco `http_output` header support cannot be confirmed offline, so enabling the token by default could silently break the attack path. Steps to enable are in `k8s/PHASE6_VERIFY.md`. Residual risk: any in-cluster pod can forge events/decisions (bounded by name validation, managed namespaces, guardrails, debounce, replica cap, and dry-run defaults). Recommended before real use: enable the token for AlertManager+Falco and the dashboard token. | n/a |
| dashboard restore keys quarantines by bare pod name, so identical pod names in two namespaces collapse in the UI | **not changed** | the grid, forensics file names and the demo store are all keyed by pod name; fixing it means re-keying the whole UI. Impact is limited to display of same-named pods across namespaces (the cluster policies and DB rows are correct and namespaced). | n/a |
| `logs/guardrail_audit.jsonl` shows 65 added lines | bookkeeping | it was already modified when this session started and my early (pre-isolation) baseline runs appended more; the test suite now writes to a temp dir. CLAUDE.md already says never to commit this file; do not stage it. I did not revert it because that would also discard whatever you had in it. | n/a |
