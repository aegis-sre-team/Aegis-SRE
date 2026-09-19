# Aegis-SRE: Phase Plan (Rebuild Baseline)

> **Status rule:** Nothing is DONE until its success criteria pass on a real cluster (or, for software-only phases, against live sensors — not dry-run fakes).
>
> **Canonical target:** Online Boutique (`online-boutique`) + chaos in `aegis-chaos` + control plane later in `aegis-system`.
>
> **Reuse:** Existing `src/` and `controller/` code is the software base. We harden and wire it phase-by-phase; we do not treat false prior checkmarks as complete.

---

## Build Order

```
Phase 1 → Infrastructure Lab (Boutique + Chaos + K3s)
Phase 2 → Sensory System (Prometheus + AlertManager + Falco + Loki + Cilium)
Phase 3 → Diagnostic Brain (Collector + RAG + LLM)
Phase 4 → Decision Engine (Guardrails)
Phase 5 → Action Muscle (Executor + Go Controller + Cilium quarantine)
Phase 6 → Immune Response (Verify + Escalate E2E)
Phase 7 → Command Center (Live Dashboard)
```

Do not start Phase N+1 until Phase N success criteria are green. No post-Phase-7 wishlist in this plan.

---

## Whole-Project Gap Map

| Phase | Reuse | Must build / fix | Status |
|---|---|---|---|
| 1 | Boutique YAML | Namespaces, real chaos suite, OCI K3s live, single apply path | **DONE** (oracle-k3s) |
| 2 | `config/` compose patterns | K8s Falco/Loki/Promtail/AlertManager, alert rules, Cilium | **DONE** (oracle-k3s) |
| 3 | Brain / RAG / LLM code | Honest collector, alert ingest, prompt `confidence` | **DONE** (oracle-k3s) |
| 4 | Guardrails + unit tests | DB-backed rate limits / decision persistence | **DONE** (oracle-k3s + Neon) |
| 5 | Python executor + Go scaffold | `AEGIS_DRY_RUN`, Go deploy, live quarantine | **NOT DONE** |
| 6 | Pipeline / benchmark structure | Live verify→escalate on real chaos | **NOT DONE** |
| 7 | Dashboard UI shell | Live pods, real forensics, honest sensor health | **NOT DONE** |

---

## Phase 1 — Infrastructure Lab

**Goal:** A live K3s lab with Online Boutique running and chaos pods that produce measurable anomalies.

**Status:** DONE (validated on `oracle-k3s` / `aegis-primary-vnic`)

### Deliverables

| Path | Purpose |
|---|---|
| `k8s/00-namespace.yaml` | `aegis-chaos`, `aegis-system` (+ boutique ns is in boutique manifest) |
| `k8s/online-boutique/online-boutique.yaml` | Primary target microservices |
| `k8s/chaos/*.yaml` | Real injectors: OOM, CPU, crashloop, shell, HTTP 500 |
| `PHASE1_CLOUD_SETUP.md` | OCI + K3s provisioning |

**Canonical chaos lives under `k8s/chaos/`.** Do not use `deploy/k8s/03-chaos/` (deprecated idle runner).

### Apply order (after `kubectl get nodes` works)

```bash
# From repo root, with KUBECONFIG pointed at the cluster
kubectl config use-context oracle-k3s
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/online-boutique/online-boutique.yaml
kubectl apply -f k8s/chaos/
```

### Verify Boutique

```bash
kubectl get pods -n online-boutique
kubectl get svc -n online-boutique
# Expect frontend and core services Running / Ready
```

### Trigger and verify chaos (one at a time)

| Scenario | Apply / scale | What you should see |
|---|---|---|
| OOM | `kubectl scale deploy/chaos-oom -n aegis-chaos --replicas=1` | Pod OOMKilled or high memory; restarts |
| CPU | `kubectl scale deploy/chaos-cpu-spike -n aegis-chaos --replicas=1` | Sustained high CPU on the pod |
| CrashLoop | `kubectl scale deploy/chaos-crashloop -n aegis-chaos --replicas=1` | `CrashLoopBackOff` |
| Shell (T1059 bait) | `kubectl scale deploy/chaos-shell-injection -n aegis-chaos --replicas=1` | Shell process in container (Falco in Phase 2) |
| HTTP 500 flood | `kubectl scale deploy/chaos-http-500 -n aegis-chaos --replicas=1` | Load / error-path hits on boutique frontend |

Scale chaos Deployments back to `0` when done:

```bash
kubectl scale deploy -n aegis-chaos --all --replicas=0
```

### Success criteria

- [x] `kubectl get nodes` shows a healthy ARM (or lab) node
- [x] Online Boutique pods are Running and the store frontend is reachable
- [x] Each of the five chaos scenarios produces a measurable anomaly
- [x] Cluster is reachable from your workstation via `kubectl`

### Cloud handoff

1. Follow `PHASE1_CLOUD_SETUP.md` Steps 1–5 (OCI instance → firewall → K3s → kubeconfig → eBPF check).
2. Run the apply order above (Step 6 in that guide).
3. Run Boutique + chaos verify commands; check every box above.
4. Use the short checklist in `k8s/PHASE1_VERIFY.md` and reply when `kubectl get nodes` works so Phase 1 can be validated live.
5. When all Phase 1 boxes are checked, start Phase 2.

---

## Phase 2 — Sensory System

**Goal:** Cluster pain is visible — metrics, kernel security events, and logs.

**Status:** DONE (validated on `oracle-k3s`)

### Deliverables

| Path | Purpose |
|---|---|
| `k8s/monitoring/prometheus.yaml` | Prometheus + cAdvisor scrape + `AegisHighPodCPU` rule |
| `k8s/monitoring/alertmanager.yaml` | AlertManager (Phase 3 wires brain webhook) |
| `k8s/monitoring/loki.yaml` | Loki log store |
| `k8s/monitoring/promtail.yaml` | Promtail DaemonSet (K8s SD; `namespace`/`pod`/`app` labels) |
| `k8s/monitoring/falco.yaml` | Falco modern_ebpf DaemonSet + MITRE rules → stdout |
| `k8s/monitoring/grafana.yaml` | Grafana + Prometheus/Loki datasources |
| `k8s/cilium/` | Helm values + Path A install (Flannel → Cilium) |
| `k8s/PHASE2_VERIFY.md` | Live verify checklist |

### Reuse

- `config/prometheus/`, `config/loki/`, `config/promtail/`, `config/falco/`, `config/grafana/`
- `k8s/monitoring/prometheus.yaml` (extended; do not treat prior draft as complete)

### Apply order

```bash
kubectl config use-context oracle-k3s
kubectl apply -f k8s/monitoring/prometheus.yaml
kubectl apply -f k8s/monitoring/alertmanager.yaml
kubectl apply -f k8s/monitoring/loki.yaml
kubectl apply -f k8s/monitoring/promtail.yaml
kubectl apply -f k8s/monitoring/falco.yaml
kubectl apply -f k8s/monitoring/grafana.yaml
# Cilium (Path A): follow k8s/cilium/INSTALL.md
```

### Falco → Loki label (collector contract)

- Falco DaemonSet pod label: `app: falco`
- Promtail ships stdout → Loki stream `{app="falco"}`
- Matches `src/brain/collector.py` (`fetch_falco_alerts` queries `{app="falco"}`)

### Success criteria

- [x] Prometheus scrapes Boutique (+ chaos) metrics (via cAdvisor; app `/metrics` often gRPC)
- [x] AlertManager fires on sustained high CPU (`AegisHighPodCPU`, ~70–80% of limit for ~1–2m)
- [x] Falco events appear in Loki when shell chaos runs (`{app="falco"}` contains `T1059` / `SECURITY_ALERT`)
- [x] Promtail tags logs with pod/namespace labels
- [x] Cilium is the cluster CNI (Path A; `cilium status --brief` = OK; `CiliumNetworkPolicy` CRD present)

### Notes from live cutover

- K3s CRI socket for Falco: `/run/k3s/containerd/containerd.sock`
- After Cilium install, restart monitoring + Boutique so pods get Cilium endpoints
- Keep `loadgenerator` at replicas=0 on this single-node ARM box unless intentionally load-testing

---

## Phase 3 — Diagnostic Brain

**Goal:** Alert evidence → RAG context → LLM JSON diagnosis.

**Status:** DONE (validated on `oracle-k3s` / `aegis-system`)

### Deliverables (to build / fix)

- Honest `TelemetryCollector` (no fake healthy defaults when sensors fail)
- AlertManager (or Falco) → brain ingest webhook
- Prompt schema includes `confidence` and `SCALE_DEPLOYMENT`
- Ollama on ARM and/or configured Groq/Gemini fallback

### Reuse

- `src/brain/` (diagnostic_engine, rag_engine, llm_client, metric_serializer, knowledge_base)

### Deploy / apply

```bash
kubectl config use-context oracle-k3s
# Build ARM image (from repo root, Docker Desktop + buildx):
#   docker buildx build --platform linux/arm64 -f Dockerfile.brain -t aegis-brain:phase3 \
#     --output type=docker,dest=aegis-brain-phase3.tar .
# Import on node (SSH): sudo k3s ctr images import aegis-brain-phase3.tar
kubectl apply -f k8s/00-namespace.yaml
kubectl -n aegis-system create secret generic aegis-brain-secrets \
  --from-literal=GROQ_API_KEY="$GROQ_API_KEY" \
  --from-literal=GROQ_MODEL="${GROQ_MODEL:-openai/gpt-oss-20b}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f k8s/brain/brain.yaml
kubectl apply -f k8s/monitoring/alertmanager.yaml
kubectl rollout restart deploy/alertmanager -n monitoring
```

In-cluster endpoints wired:

- Prometheus: `http://prometheus.monitoring.svc:9090`
- Loki: `http://loki.monitoring.svc:3100`
- AlertManager webhook: `http://aegis-brain.aegis-system.svc:8001/api/v1/alerts/webhook`

See `k8s/PHASE3_VERIFY.md`.

### Success criteria

- [x] RAG returns relevant runbooks for OOM vs shell alerts
- [x] LLM (or fallback) classifies shell as ATTACK and OOM as BUG in test runs
- [x] Output JSON is parseable by guardrails
- [x] Dark sensors escalate / fail closed instead of inventing healthy metrics

### Live proof notes (oracle-k3s)

- `/health`: prometheus+loki+falco_via_loki ok; `rag_docs_indexed=12`
- `OOM_KILLED_RISK` → `OPERATIONAL_BUG` / `RESTART_POD` (confidence ≥ 0.90)
- `falco_shell_spawn` with shell chaos → `SECURITY_ATTACK` / `CILIUM_QUARANTINE_EBPF` (Falco events from `{app="falco"}`)
- AlertManager webhook `AegisHighPodCPU` → `OPERATIONAL_BUG` / `SCALE_DEPLOYMENT`
- Dark Prom/Loki → `SENSOR_DARK` / `ESCALATE` / confidence `0.0`

---

## Phase 4 — Decision Engine (Guardrails)

**Goal:** Validate LLM actions before anything touches the cluster.

**Status:** DONE (validated on `oracle-k3s` / Neon Postgres + in-cluster brain)

### Deliverables (to build / fix)

- Keep blocklist, allowlist, confidence ≥ 0.70, restart rate limit
- Persist rate-limit / audit decisions to DB (not only in-memory / JSONL)
- Ensure action names match knowledge base + executor (`CILIUM_QUARANTINE_EBPF`, etc.)
- Schema validation before controller (`LLMVerdictSchema` + `validate_controller_decision`)

### Reuse

- `src/guardrails/`, `src/db/`, `test/test_guardrails.py`

### Deploy / apply

```bash
kubectl config use-context oracle-k3s
# Patch secrets (do not commit values). DATABASE_URL = Neon from local .env preferred.
kubectl -n aegis-system create secret generic aegis-brain-secrets \
  --from-literal=GROQ_API_KEY="$GROQ_API_KEY" \
  --from-literal=GROQ_MODEL="${GROQ_MODEL:-openai/gpt-oss-20b}" \
  --from-literal=DATABASE_URL="$DATABASE_URL" \
  --dry-run=client -o yaml | kubectl apply -f -
# Rebuild ARM image → scp → sudo k3s ctr images import (same path as Phase 3)
kubectl apply -f k8s/brain/brain.yaml
kubectl -n aegis-system rollout restart deploy/aegis-brain
```

In-cluster: `AEGIS_DRY_RUN=true`; guardrails persist to Neon when `DATABASE_URL` is set (else SQLite under `/data`).

### Success criteria

- [x] Blocked actions rejected with logged reason
- [x] Confidence threshold enforced
- [x] Schema validation before controller
- [x] Restart frequency limit survives process restart (DB-backed)
- [x] Unit tests still pass

### Live proof notes (oracle-k3s)

- `/health` → `version=1.5.0`, `database.backend=postgres`, `guardrails.persist=true`, `dry_run=true`
- Controller `POST /api/v1/controller/execute` with `DELETE_NAMESPACE` → HTTP 400 (`not in ALLOWED_ACTIONS`)
- In-pod: blocklist → `STATE_ACTION_REJECTED`; confidence 0.40 → `STATE_ESCALATE_HUMAN`
- In-pod: 3× `RESTART_POD` recorded in Neon `restart_events`; 4th rejected (`rate_limit_exceeded`)
- After brain pod delete/recreate: same pod still rate-limited (3 rows survived in Neon)

---

## Phase 5 — Action Muscle

**Goal:** Approved actions execute via Kubernetes API + Cilium quarantine.

**Status:** NOT DONE (dry-run only today)

### Deliverables (to build / fix)

- `AEGIS_DRY_RUN` env flag (default safe; false on live cluster)
- Go controller Dockerfile + K8s Deployment/Service in `aegis-system`
- Live RESTART / SCALE / QUARANTINE / UNQUARANTINE against Boutique labels
- DFIR snapshot on quarantine

### Reuse

- `src/controller/`, `controller/main.go`, `controller/reconciler.go`

### Success criteria

- [ ] With dry-run off, RESTART rolls a real pod
- [ ] QUARANTINE applies Cilium policy and blocks traffic
- [ ] UNQUARANTINE restores connectivity
- [ ] Controller audit log records outcomes

---

## Phase 6 — Immune Response

**Goal:** Full BUG and ATTACK paths with verify → escalate.

**Status:** NOT DONE

### Deliverables (to build / fix)

- End-to-end: chaos → alert → diagnose → guard → act → verify
- Failed verification → `STATE_ESCALATE_HUMAN` + notification
- Live (not synthetic-only) Cloud-OpsBench scenarios against Phase 1 chaos

### Reuse

- `src/brain/main.py` pipeline, `test/test_chaos_benchmark.py` structure, notifications

### Success criteria

- [ ] Bug path: resource chaos → restart/scale → healthy
- [ ] Attack path: shell chaos → quarantine → traffic blocked
- [ ] Failed remediation escalates to human
- [ ] Forensics captured on security path

---

## Phase 7 — Command Center

**Goal:** Real-time view of reasoning and cluster state.

**Status:** NOT DONE (UI shell exists; data is simulated)

### Deliverables (to build / fix)

- Live pod grid from Prometheus / Kubernetes API
- WebSocket stream of LLM + controller events
- Quarantine list + real DFIR (no invented forensics)
- HITL drawer calling the real executor
- Honest startup health checks for Prom/Loki/Falco

### Reuse

- `src/dashboard/`

### Success criteria

- [ ] Dashboard reflects live Boutique / chaos pod state
- [ ] Reasoning and actions stream within seconds of a trigger
- [ ] HITL can approve/dispatch real remediation
- [ ] No fake “sensors connected” when they are down

---

## Definition of Done (project)

1. Chaos CPU/OOM → autonomous heal (restart/scale) verified healthy
2. Shell chaos → quarantine in under ~60s with traffic blocked
3. Dashboard shows the full reasoning chain for both
4. Guardrails block a injected `DELETE_NAMESPACE`
5. Stack runs on zero-cost lab infra (Oracle Always Free ± free-tier dashboard host)

---

*Rebuild baseline — Phase 1–4 DONE on oracle-k3s; Phase 5–7 NOT DONE until criteria pass.*
