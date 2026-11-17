# Phase 6 verify: immune response (run on the live cluster)

> **Status:** the loop is built and unit-tested offline: `src/brain/remediation.py` (`process_alert`), verification in `ActionExecutor.verify_remediation_health`, the Falco ingest endpoint, and escalation. This checklist proves it against real chaos. Do `PHASE5_VERIFY.md` first.
>
> Pipeline: **alert -> diagnose -> guardrails -> controller acts -> verify (poll controller `/status`) -> escalate on any failure**.
> Bug alerts come from AlertManager (`/api/v1/alerts/webhook`); security events come from Falco (`/api/v1/alerts/falco`, `http_output`).

## 0. Enable

```bash
export KUBECONFIG=~/.kube/aegis-aws.yaml
kubectl apply -f k8s/monitoring/falco.yaml           # http_output + ns= in rule output
kubectl -n monitoring rollout restart ds/falco
kubectl -n aegis-system set env deploy/aegis-controller DRY_RUN=false
kubectl -n aegis-system set env deploy/aegis-brain AEGIS_DRY_RUN=false AEGIS_AUTO_REMEDIATE=true
kubectl -n aegis-system rollout status deploy/aegis-brain
```

Falco reaches the brain? From the Falco pod logs (`kubectl -n monitoring logs ds/falco | grep -i http`) there must be no repeated connection errors.

## 1. Bug path: CPU chaos -> heal -> verified

```bash
kubectl scale deploy/chaos-cpu-spike -n aegis-chaos --replicas=1
# wait ~2 min for AegisHighPodCPU -> AlertManager -> brain
kubectl -n aegis-system logs deploy/aegis-brain --since=5m | grep -E "Diagnosis|ESCALATED|GUARDRAIL"
```

Expected: a diagnosis for a pod in `aegis-chaos`, guardrails approve a heal action, the controller log shows the action, and no `ESCALATED` line.

- [ ] the chaos deployment was acted on (restart or scale) without human input
- [ ] `kubectl -n aegis-chaos get pods` is healthy afterwards (or the replacement pod is Running)
- [ ] the brain response/log says `verified: true`

Note: the rule-based fallback and the LLM pick the action; for a bare CPU stress pod `RESTART_POD` is expected. If the guardrails escalate instead, read the reason in the log; that is also a valid, safe outcome to record.

## 2. Attack path: shell injection -> quarantine -> blocked

```bash
kubectl scale deploy/chaos-shell-injection -n aegis-chaos --replicas=1
sleep 20
kubectl -n monitoring logs ds/falco --since=2m | grep -i "Aegis Shell"            # Falco saw it
kubectl -n aegis-system logs deploy/aegis-brain --since=2m | grep -E "falco_shell_spawn|quarantine|QUARANTINE"
kubectl -n aegis-chaos get ciliumnetworkpolicy                                    # aegis-quarantine-<pod>
kubectl -n aegis-chaos get pods -L aegis.io/quarantine-target                     # pod still exists, labelled
```

- [ ] quarantine happened within about 60 s of the shell event (Definition of Done #2)
- [ ] the pod was NOT restarted (same pod name, same start time)
- [ ] traffic is blocked (the probe commands in `PHASE5_VERIFY.md` section 6)
- [ ] the forensics file exists and contains real events/logs: `kubectl -n aegis-system exec deploy/aegis-brain -- sh -c 'cat /app/logs/forensics_*.json | head -60'`
- [ ] repeated Falco events inside 30 s did not cause repeated quarantines (debounce; the log shows `debounced`)

## 3. Failed remediation escalates

Force a failure by making the controller unable to act, then trigger an alert:

```bash
kubectl -n aegis-system scale deploy/aegis-controller --replicas=0
kubectl scale deploy/chaos-oom -n aegis-chaos --replicas=1     # or re-trigger any alert
kubectl -n aegis-system logs deploy/aegis-brain --since=5m | grep -E "FAILED_CONTROLLER_UNREACHABLE|ESCALATED"
```

- [ ] the brain logs `Execution failed (FAILED_CONTROLLER_UNREACHABLE)` and `ESCALATED`
- [ ] an entry appears in `logs/escalations.jsonl` (and the webhook, if `AEGIS_ESCALATION_WEBHOOK` is set)
- [ ] nothing was reported as healed

Then restore: `kubectl -n aegis-system scale deploy/aegis-controller --replicas=1`.

Second drill, failed verification: set `VERIFY_TIMEOUT_S=15` on the brain, break the workload so it cannot become ready (for example scale `chaos-crashloop` to 1 and let guardrails restart it), and confirm the brain escalates with "Post-remediation verification failed".

- [ ] failed verification produced `STATE_ESCALATE_HUMAN` + notification

## 4. Guardrail drills

```bash
BRAIN=$(kubectl -n aegis-system get pod -l app=aegis-brain -o name | head -1)
kubectl -n aegis-system exec $BRAIN -- python - <<'EOF'
from src.guardrails import GuardrailEngine
g = GuardrailEngine()
for v in ({"target_pod":"x","problem_type":"OPERATIONAL_BUG","recommended_action":"DELETE_NAMESPACE","confidence":0.99,"namespace":"online-boutique"},
          {"target_pod":"coredns-1","problem_type":"OPERATIONAL_BUG","recommended_action":"RESTART_POD","confidence":0.99,"namespace":"kube-system"}):
    d = g.validate_verdict(v); print(d.state, d.final_action, d.reason)
EOF
```

- [ ] `DELETE_NAMESPACE` -> `STATE_ACTION_REJECTED`; `kube-system` restart -> `STATE_ACTION_REJECTED`

## 5. Put it back

```bash
kubectl -n aegis-system set env deploy/aegis-brain AEGIS_AUTO_REMEDIATE=false AEGIS_DRY_RUN=true
kubectl -n aegis-system set env deploy/aegis-controller DRY_RUN=true
kubectl scale deploy/chaos-cpu-spike deploy/chaos-shell-injection deploy/chaos-oom deploy/chaos-crashloop -n aegis-chaos --replicas=0
```

## Known assumptions this checklist exists to test

- Falco's `http_output` payload carries `k8s.pod.name` and `k8s.ns.name` in `output_fields` (they are in the rule output text, which is what puts them there). If Falco reports `<NA>` for a container, the event is ignored by design.
- The Cilium deny policy is accepted and enforced (see `PHASE5_VERIFY.md`).
- `ps` may be missing in minimal chaos images; the snapshot then lists the reason in `errors` instead of inventing a process list.

## 6. Hardening checks (added after the code review)

```bash
# a. OOM and crash-loop chaos now reach the brain (rules AegisContainerOOMKilled / AegisPodCrashLooping)
kubectl scale deploy/chaos-oom -n aegis-chaos --replicas=1
kubectl -n monitoring port-forward svc/prometheus 9090:9090 &
curl -s localhost:9090/api/v1/rules | grep -o '"name":"Aegis[A-Za-z]*"'     # all three Aegis alerts listed
# wait a few minutes, then:
kubectl -n aegis-system logs deploy/aegis-brain --since=10m | grep -E "OOM_KILLED_RISK|CRASHLOOP_BACKOFF"
```

- [ ] OOM chaos produces an `OOM_KILLED_RISK` diagnosis; crash-loop chaos (`chaos-crashloop`) produces `CRASHLOOP_BACKOFF`
- [ ] after 3 restarts of the same Deployment (even though each restart renames the pod) the guardrail escalates instead of restarting again (look for `rate_limit_exceeded`)
- [ ] Falco `Aegis Sensitive File Read` no longer fires for an ordinary `id` / `ls -l` (they read `/etc/passwd`); `kubectl exec` into a chaos pod and `cat /etc/shadow` does fire it
- [ ] Falco events from `kube-system`/`monitoring` are ignored (brain log: `Ignoring Falco event outside the managed namespaces`), with no LLM call and no escalation
- [ ] the cAdvisor scrape target is UP with TLS verification on (Prometheus `/targets`); if it is DOWN, the API-server certificate SANs are the first suspect (the previous config skipped verification)

### Optional: require a shared token on the brain's action endpoints

```bash
TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
kubectl -n aegis-system set env deploy/aegis-brain AEGIS_INGEST_TOKEN=$TOKEN
# AlertManager and Falco must then send it (X-Aegis-Token header or Authorization: Bearer):
#  - AlertManager: add `http_config: {authorization: {credentials: <TOKEN>}}` to the webhook receiver
#  - Falco: add `custom_headers: {X-Aegis-Token: <TOKEN>}` under http_output (needs a live check)
```

- [ ] without the header the endpoints answer 401; with it they work; `/health` stays open

Until both senders are configured, leave `AEGIS_INGEST_TOKEN` unset (the endpoints are then open inside the cluster).
