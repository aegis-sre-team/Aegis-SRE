# Aegis-SRE

**Autonomous self-healing infrastructure for cloud-native Kubernetes environments.**

Aegis-SRE acts as an adaptive immune system for clusters: it observes telemetry and kernel-level security signals, diagnoses incidents with a local LLM and RAG knowledge base, then either **heals** operational failures or **defends** against active threats — without treating every alert the same way.

[![Kubernetes](https://img.shields.io/badge/Kubernetes-K3s-326CE5)](https://k3s.io/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20(Llama%203.2%20%2F%203.1)-green)](https://ollama.com/)
[![Falco](https://img.shields.io/badge/Security-Falco%20%2B%20eBPF-blue)](https://falco.org/)
[![Cilium](https://img.shields.io/badge/Network-Cilium-F8C517)](https://cilium.io/)

---

## Why Aegis-SRE?

Traditional auto-remediation often defaults to “restart the pod.” That works for a memory leak. It fails for an active intrusion — restarting under attack can wipe forensic state while the attacker still has a foothold.

Aegis classifies each incident into one of two paths:

| Problem type | Examples | Response |
|---|---|---|
| **Operational bug** | Memory leak, OOMKill, CrashLoopBackOff, CPU throttling | **Heal** — rollout restart, scale deployment |
| **Security attack** | Reverse shell, credential scrape, network recon (MITRE ATT&CK) | **Defend** — Cilium eBPF quarantine; preserve pod for DFIR |

**Core idea:** restarting a container under active intrusion does not eliminate the attacker. Aegis isolates security threats while keeping container state available for forensics.

---

## Features

- **Dual-path remediation** — operational heal vs. security isolate, driven by LLM diagnosis + rule guardrails
- **Local LLM brain** — Ollama (`llama3.2:3b` / `llama3.1:8b`) with optional Groq / Gemini free-tier backends
- **RAG knowledge base** — SRE runbooks + MITRE ATT&CK technique notes for grounded diagnoses
- **Guardrail safety engine** — action blocklists, confidence thresholds, restart rate limits, human escalation
- **Go Kubernetes controller** — executes approved actions (restart, scale, Cilium NetworkPolicy quarantine)
- **Observability stack** — Prometheus, Loki/Promtail, Falco (eBPF), Grafana
- **Real-time dashboard** — FastAPI + WebSockets mission control with HITL remediation and DFIR views
- **Chaos / Cloud-OpsBench tests** — automated suite covering operational and security failure categories
- **Zero-cost cloud path** — designed for Oracle Cloud Always Free ARM + optional free-tier monitoring host

---

## Architecture

### Mental model

| Component | Role |
|---|---|
| **Prometheus** | Telemetry sensors (CPU, memory, error rates) |
| **Falco** | Kernel/eBPF security sensors (unauthorized process, sensitive file access) |
| **Loki + Promtail** | Centralized log aggregation |
| **Ollama + RAG** | Diagnostic brain — classifies incidents using runbooks and MITRE notes |
| **Guardrails** | Safety layer — vetoes destructive or low-confidence actions |
| **Go controller** | Execution muscle — applies Kubernetes and Cilium changes |
| **Cilium** | eBPF network isolation cage for quarantined pods |
| **Dashboard** | Human oversight — live telemetry, approve/escalate, forensics |

### End-to-end pipeline

```text
Sensors (Prometheus / Falco / Loki)
        │
        ▼
Telemetry collector + metric serialization
        │
        ▼
RAG retrieval (runbooks + MITRE TTPs)
        │
        ▼
LLM diagnosis → structured verdict
        │
        ▼
Guardrail engine (blocklist / confidence / rate limits)
        │
        ├── APPROVED → Go controller → restart | scale | Cilium quarantine
        └── REJECTED / LOW CONFIDENCE → escalate to human
        │
        ▼
Verification loop → healthy? log success : escalate again
```

### Remediation paths

**Path A — Operational bug**

```text
Alert: OOMKilled on checkout-service
  → LLM: memory leak, no threat indicators
  → Action: RESTART_POD
  → Guardrails: approved (confidence + rate limits OK)
  → Controller: rollout restart, re-check health
```

**Path B — Security threat**

```text
Alert: Falco — shell spawned in container (T1059)
  → LLM: active intrusion
  → Action: CILIUM_QUARANTINE_EBPF
  → Guardrails: approved (isolation preferred over restart)
  → Controller: Cilium NetworkPolicy → DROP ingress/egress
  → Pod preserved for DFIR
```

### Target cloud layout

```text
┌─────────────────────────────────────────────────────┐
│          Oracle ARM A1 — Always Free                │
│          4 OCPU | 24 GB RAM | K3s                   │
│                                                     │
│  Microservices + chaos injection                    │
│    → Prometheus + Falco + Loki                      │
│    → Ollama + RAG                                   │
│    → Guardrails → Go controller                     │
│    → Cilium NetworkPolicy isolation                 │
└───────────────────────┬─────────────────────────────┘
                        │ VPN (e.g. Tailscale)
                        ▼
┌─────────────────────────────────────────────────────┐
│          Optional monitoring host (e.g. Azure)      │
│          FastAPI + WebSockets dashboard             │
└─────────────────────────────────────────────────────┘
```

Local development uses Docker Compose with the same conceptual layers (target app, Prometheus, Loki, Falco, dashboard, Grafana).

---

## Repository layout

```text
Aegis-SRE/
├── src/
│   ├── brain/              # Diagnostic engine, LLM client, RAG, collectors
│   ├── guardrails/         # Action schema + safety validator
│   ├── controller/         # Python executor + Cilium policy helpers
│   ├── dashboard/          # FastAPI mission control + static UI
│   ├── db/                 # SQLite persistence models
│   ├── knowledge_base/     # Runbooks + MITRE security notes
│   └── target_app/         # Demo e-commerce / chaos target app
├── controller/             # Go Kubernetes action controller (client-go)
├── config/                 # Prometheus, Loki, Promtail, Falco, Grafana
├── deploy/
│   ├── docker-compose.yml  # Local full stack
│   └── k8s/                # Namespace, target app, chaos suite manifests
├── k8s/
│   ├── monitoring/         # Cluster monitoring manifests
│   └── online-boutique/    # Online Boutique workload manifests
├── test/                   # Unit, integration, chaos benchmark suites
├── scripts/                # Public tunnel helpers (Cloudflare)
├── PHASE1_CLOUD_SETUP.md   # Oracle Cloud K3s provisioning guide
├── PHASES.md               # Phased build plan
└── requirements.txt
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Cluster | K3s / Docker Compose |
| Metrics | Prometheus + Alertmanager |
| Security sensing | Falco + eBPF |
| Logs | Loki + Promtail |
| Visualization | Grafana |
| AI diagnosis | Ollama (Llama 3.2 3B / 3.1 8B); optional Groq / Gemini |
| Memory / RAG | TF-IDF retrieval over runbooks and MITRE notes |
| Guardrails | Python safety engine |
| Controller | Go + `client-go` |
| Isolation | Cilium NetworkPolicy |
| Dashboard | FastAPI + WebSockets |
| Persistence | SQLite (local); optional cloud Postgres |

---

## Prerequisites

- **Python** 3.10+
- **Docker** and Docker Compose (for the full local stack)
- **Go** 1.21+ (optional — only to build/run the native controller)
- **Ollama** (recommended for local LLM inference) — [ollama.com](https://ollama.com)
- **kubectl** + a kubeconfig (for real cluster control; dry-run works without it)

Optional free-tier AI keys (if not using Ollama): Groq or Google Gemini — see [`.env.example`](.env.example).

---

## Quick start

### 1. Clone and configure

```bash
git clone <repo-url> Aegis-SRE
cd Aegis-SRE
cp .env.example .env
```

Edit `.env` as needed. Minimum for local LLM:

```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
PROMETHEUS_URL=http://localhost:9090
LOKI_URL=http://localhost:3100
TARGET_APP_URL=http://localhost:5000
```

Pull a model if using Ollama:

```bash
ollama pull llama3.2:3b
# or: ollama pull llama3.1:8b
```

### 2. Run with Docker Compose (recommended)

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

| Service | URL |
|---|---|
| Aegis dashboard | http://localhost:8000 |
| Target app | http://localhost:5000 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 (`admin` / `admin`) |
| Loki | http://localhost:3100 |

### 3. Run the dashboard locally (without full Compose)

```bash
pip install -r requirements.txt
# PowerShell
$env:PYTHONPATH="."
python -m src.dashboard.server
```

```bash
# bash
export PYTHONPATH=.
python -m src.dashboard.server
```

Open http://localhost:8000.

### 4. Go controller (optional)

```bash
cd controller
go run .
```

Health check: `GET /healthz`. Without a valid kubeconfig the controller runs in offline/dry-run mode.

---

## Configuration

All primary settings live in [`.env.example`](.env.example):

| Variable | Purpose |
|---|---|
| `OLLAMA_HOST` / `OLLAMA_MODEL` | Local LLM endpoint and model |
| `GROQ_API_KEY` / `GEMINI_API_KEY` | Optional cloud LLM backends |
| `PROMETHEUS_URL` / `LOKI_URL` / `TARGET_APP_URL` | Telemetry and target endpoints |
| `DATABASE_URL` / `AEGIS_DB_DIR` | SQLite state and logs directory |
| `AEGIS_ESCALATION_WEBHOOK` | Discord/Slack webhook for human escalation |
| `GO_CONTROLLER_URL` | Reconcile API for the Go action controller |

Sensor configs are under `config/` (Prometheus scrape targets, Falco rules, Loki/Promtail, Grafana datasources).

---

## Guardrails and safety

Before any remediation runs, the **Guardrail Engine** validates the LLM verdict:

- **Catastrophic blocklist** — e.g. `DELETE_NAMESPACE` and other destructive actions are rejected
- **Confidence gate** — default minimum confidence ≥ **0.70**; otherwise escalate to a human
- **Rate limits** — max **3** pod restarts per hour per target (prevents restart storms)
- **Security preference** — active intrusion signals favor **quarantine** over blind restart
- **Audit logging** — decisions recorded for review and escalation trails

Verification after action:

```text
Action taken → re-check sensors → still broken? → escalate
                              → healthy?      → log success
```

---

## Security: MITRE ATT&CK mapping

| Signal / Falco alert | MITRE technique | Typical Aegis action |
|---|---|---|
| Shell spawned in container | T1059 — Command and Scripting Interpreter | `CILIUM_QUARANTINE_EBPF` |
| Sensitive file read (`/etc/shadow`, etc.) | T1552 — Unsecured Credentials | `CILIUM_QUARANTINE_EBPF` |
| Network discovery tools | T1046 — Network Service Discovery | `CILIUM_QUARANTINE_EBPF` |
| Valid account / suspicious auth patterns | T1078 — Valid Accounts | Quarantine / escalate |
| Endpoint DoS / resource exhaustion attack | T1499 — Endpoint Denial of Service | Quarantine / scale as appropriate |
| Cryptomining process patterns | Resource Hijacking | `CILIUM_QUARANTINE_EBPF` |
| Memory spike + OOMKill (no threat indicators) | Operational | `RESTART_POD` |
| CPU throttling loop | Operational | `SCALE_DEPLOYMENT` |

Knowledge base documents live in:

- `src/knowledge_base/runbooks/` — operational SRE playbooks
- `src/knowledge_base/security/` — MITRE-oriented security notes

Falco local rules: `config/falco/`.

---

## Knowledge base

Operational runbooks include OOM, CrashLoopBackOff, CPU throttling, HTTP 500 spikes, DB connection pool exhaustion, and circuit-breaker trips.

Security notes cover command execution, credential access, network recon, valid accounts, endpoint DoS, and cryptomining.

The RAG engine retrieves relevant documents at diagnosis time so the LLM grounds recommendations in project-specific guidance rather than generic guesses.

---

## Testing

The repository includes automated suites for guardrails, controller behavior, pipeline integration, edge cases, dashboard APIs, and an 8-category chaos / Cloud-OpsBench-style benchmark.

```powershell
$env:PYTHONPATH="."; python -m unittest discover -s test -p "test_*.py"
```

```bash
export PYTHONPATH=.
python -m unittest discover -s test -p "test_*.py"
```

Run the chaos benchmark alone:

```powershell
$env:PYTHONPATH="."; python test/test_chaos_benchmark.py
```

Reports and logs (when generated) appear under `logs/` (e.g. benchmark JSON, executive markdown, escalation JSONL).

Additional hands-on notes: [`test/HANDS_ON_GUIDE.md`](test/HANDS_ON_GUIDE.md).

---

## Kubernetes and cloud deployment

### Local / lab manifests

- `deploy/k8s/` — namespace, target app, chaos suite
- `k8s/online-boutique/` — Google Online Boutique–style microservice workload
- `k8s/monitoring/` — cluster monitoring resources

### Phase 1 cloud lab (Oracle Always Free)

Step-by-step provisioning for a **$0/month** K3s cluster on Oracle Cloud ARM A1 (4 OCPU / 24 GB RAM):

→ **[`PHASE1_CLOUD_SETUP.md`](PHASE1_CLOUD_SETUP.md)**

Phased roadmap (infrastructure → sensors → brain → guardrails → controller → immune response → dashboard):

→ **[`PHASES.md`](PHASES.md)**

### Approximate free-tier cost model

| Resource | Platform | Cost |
|---|---|---|
| K3s cluster | Oracle Cloud ARM A1 Always Free | $0/mo |
| Optional dashboard VM | Azure free-tier hours (or local) | $0/mo |
| Local LLM | Ollama on host / cluster | $0 |
| **Total** | | **$0/mo** |

### Public exposure (optional demos)

Scripts under `scripts/` can publish the local dashboard via Cloudflare quick tunnels (no custom domain required) or a named tunnel with a custom hostname. See [`SETUP_NEEDED.md`](SETUP_NEEDED.md) for tunnel and cloud integration notes.

---

## Production-oriented roadmap

Aegis is designed to move from local Compose validation to a live Kubernetes lab:

1. **Real microservice target** — Online Boutique (or equivalent) on K3s
2. **Public ingress + TLS** — Traefik/NGINX with certificates for storefront traffic
3. **Live threat injection** — controlled red-team scenarios against exposed endpoints to measure detection and eBPF containment
4. **Hybrid / multi-cluster** — extend the controller across providers (OCI ↔ Azure ↔ on-prem)

```text
Public internet (users / controlled attack traffic)
        │ HTTPS
        ▼
Ingress (Traefik / NGINX)
        │
        ▼
Online Boutique microservices
        │ telemetry
        ▼
Aegis-SRE (Prometheus + Falco → LLM → Guardrails → Go + Cilium)
```

---

## Development phases (summary)

| Phase | Focus |
|---|---|
| 1 | Cloud lab — K3s, target apps, chaos pods, connectivity |
| 2 | Sensory system — Prometheus, Falco, Loki |
| 3 | Diagnostic brain — Ollama + RAG |
| 4 | Decision engine — function calling + guardrails |
| 5 | Action muscle — Go controller + Cilium policies |
| 6 | Immune response — heal vs. defend adaptive logic |
| 7 | Command center — real-time dashboard and HITL |

Details and success criteria: [`PHASES.md`](PHASES.md).

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| Dashboard cannot reach metrics | `PROMETHEUS_URL` / Compose network; Prometheus UI at :9090 |
| LLM timeouts or empty diagnoses | Ollama running (`ollama list`); model name matches `.env` |
| Controller always dry-run | Valid `~/.kube/config` or in-cluster service account |
| Falco not emitting events | Privileged container / host mounts in Compose; local rules under `config/falco/` |
| Guardrail always escalates | Confidence below 0.70 or rate limit hit — check logs under `logs/` |

---

## License

See the repository for license terms (add or update a `LICENSE` file as appropriate for your distribution).

---

*Aegis-SRE — infrastructure that can heal itself, and isolate threats when healing is not enough.*
