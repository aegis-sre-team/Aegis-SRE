# Aegis-SRE

**Autonomous self-healing infrastructure for cloud-native Kubernetes environments.**

Aegis-SRE acts as an **adaptive immune system** for Kubernetes clusters: it observes metrics, logs, and kernel-level eBPF security signals, diagnoses incidents using an AI diagnostic engine grounded in SRE runbooks via RAG, enforces strict deterministic safety guardrails, and executes surgical interventions — distinguishing operational bugs from active security attacks.

[![Kubernetes](https://img.shields.io/badge/Kubernetes-K3s-326CE5?logo=kubernetes&logoColor=white)](https://k3s.io/)
[![Cloud](https://img.shields.io/badge/AWS-EC2%20(Graviton%20ARM64)-FF9900?logo=amazon-aws&logoColor=white)](https://aws.amazon.com/ec2/)
[![eBPF CNI](https://img.shields.io/badge/CNI-Cilium%20v1.16.6%20(TCX)-F8C517)](https://cilium.io/)
[![Security](https://img.shields.io/badge/Security-Falco%20%2B%20modern__ebpf-blue)](https://falco.org/)
[![AI Diagnosis](https://img.shields.io/badge/LLM-Groq%20LPU%20%7C%20Ollama-green)](https://groq.com/)
[![Database](https://img.shields.io/badge/Database-Neon%20Serverless%20Postgres-00E699)](https://neon.tech/)
[![Tests](https://img.shields.io/badge/Tests-232%2F232%20Passed%20(100%25)-brightgreen)](test/)

---

> **System Overview:** Aegis-SRE runs on **AWS EC2** (`t4g.xlarge` Graviton ARM64 / `t3.medium`) on Ubuntu 24.04 with kernel BTF support, running K3s, Cilium v1.16.6 (TCX mode), and the Google Online Boutique (11 microservices). It features automated AWS CLI lifecycle management (`aws/launch.sh`, `up.sh`, `down.sh`, `guard.sh`), dual-port FastAPI services (Brain API `:8001`, Mission Control Dashboard `:8000`), a modular Go action controller (`controller/`), and an automated **232-test regression battery** covering all edge cases.

---

## Why Aegis-SRE?

Traditional Kubernetes auto-remediation defaults to **"restart the pod"**. While effective for memory leaks and transient crashes, blind restarts are **catastrophic during an active security intrusion**:
1. Restarting wipes in-memory forensic evidence (volatile processes, open sockets, dropped payloads).
2. The root vulnerability remains unpatched, allowing an attacker to immediately re-infect the fresh container.
3. Rapid crash loops trigger alert storms that overwhelm SRE on-call rotations.

Aegis-SRE bifurcates all incidents into two distinct, deterministic paths:

| Incident Category | Real-World Examples | Aegis Autonomous Response |
|---|---|---|
| **Operational Bug** | Memory leak, OOMKill, CrashLoopBackOff, CPU throttling | **Heal** — Rollout restart, scale deployment, verify post-remediation health |
| **Security Intrusion** | T1059 Container Shell Spawn, T1552 Credential Scrape, T1046 Network Recon | **Defend** — Pre-quarantine DFIR snapshot capture, then zero-trust Cilium eBPF network quarantine (DROP ingress/egress) |

**Core Axiom:** *Never restart a compromised container. Capture forensics, sever network connectivity via kernel eBPF, and preserve volatile state for human investigation.*

---

## Key Features & Production Hardening

- **Dual-Path Remediation Engine:** Operational heal (restart, scale) vs. security defense (pre-quarantine DFIR snapshot + Cilium eBPF isolation).
- **Pre-Isolation DFIR Snapshotting:** Go controller captures running processes, container metadata, pod logs, and Kubernetes events *before* network quarantine is enforced.
- **Idempotent Cilium Quarantine & Unquarantine:** Re-quarantining an already isolated pod is a safe no-op that preserves original forensic snapshots. Supports operator-driven `UNQUARANTINE_POD` release.
- **AlertDebouncer Storm Suppression:** Thread-safe, bounded sliding-window debouncer (1000-key capacity, 3600s TTL) deduplicates flapping alerts, preventing LLM inference saturation and cascading restarts.
- **Fail-Closed Sensor Dark Safety:** If Prometheus or Loki becomes unreachable, the telemetry collector raises `SensorDarkError`, immediately triggering a fail-closed `ESCALATE` verdict rather than hallucinating healthy metrics.
- **RFC-1123 Ingest Edge Sanitization:** All incoming pod and namespace parameters are strictly validated against Kubernetes DNS-1123 edge naming standards (`is_valid_k8s_name()`) before reaching database queries or controller execution.
- **Workload-Keyed Restart Rate Limiter:** Tracks restart frequencies per workload deployment (`workload_key()`) rather than ephemeral pod names, capping churn to max 3 restarts/hour.
- **3-Tier AI Diagnostic Brain:** Multi-tier fallback hierarchy (Local Ollama `llama3.2:3b` → Groq Cloud LPU `openai/gpt-oss-20b` → Deterministic Rule Engine) with sub-second inference.
- **Topology-Bounded RAG Retrieval:** TF-IDF vector retrieval over 12 curated SRE operational runbooks and MITRE ATT&CK security notes.
- **Closed-Loop Health Verification:** Post-remediation polling loop (`process_alert()`) monitors pod readiness for 30s; auto-escalates to Slack/webhooks if the workload remains unhealthy.
- **Dual-Port FastAPI Architecture:** Dedicated Brain API (`:8001`) for alert ingestion and headless remediation, plus Mission Control Dashboard (`:8000`) with real-time WebSockets telemetry.
- **Modular Go Controller (`controller/`):** Pure `client-go` Kubernetes controller decoupled into `quarantine.go`, `safety.go`, `status.go`, `workload.go`, `forensics.go`, `exec.go`, and `server.go`.
- **Neon Serverless PostgreSQL Persistence:** 5 normalized tables (`incidents`, `quarantines`, `audit_logs`, `restart_events`, `guardrail_decisions`) with async SQLAlchemy and SQLite JSONL fallback.
- **AWS Lab Automation CLI (`aws/`):** Shell scripts managing instance provisioning, spot pricing (`SPOT=1`), idle shutdown alarms (`guard.sh idle-stop`), and cost budgets (`guard.sh budget`).

---

## Architecture

### System Feedback Loop

```text
                  ┌──────────────────────────────────────────────┐
                  │    Sensing Mesh (eBPF & Cluster Telemetry)   │
                  │   Prometheus (16 targets) | Loki | Falco     │
                  └──────────────────────┬───────────────────────┘
                                         │ Webhooks
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Alert Ingest & Edge Sanitization           │
                  │   RFC-1123 DNS Check | HMAC Token Auth       │
                  └──────────────────────┬───────────────────────┘
                                         │ Sanitized Alert
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Thread-Safe AlertDebouncer                 │
                  │   1000-key bounded cache | 3600s TTL         │
                  └──────────────────────┬───────────────────────┘
                                         │ Unique Alert
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Diagnostic Brain (:8001)                   │
                  │   Collector (SensorDark fail-closed)         │
                  │   TF-IDF RAG (12 SRE / MITRE Runbooks)       │
                  │   3-Tier LLM (Ollama → Groq LPU → Rules)     │
                  └──────────────────────┬───────────────────────┘
                                         │ Diagnosis + Action Proposal
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Deterministic Safety Guardrail Engine      │
                  │   Catastrophic Blocklists (DELETE_NAMESPACE) │
                  │   Workload-keyed Rate Limiter (3/hr)         │
                  │   Confidence Threshold (≥ 0.70 floor)        │
                  └──────────┬────────────────────────┬──────────┘
                             │                        │
                   [APPROVED ACTION]        [REJECTED / LOW CONFIDENCE]
                             │                        │
                             ▼                        ▼
        ┌──────────────────────────────┐   ┌──────────────────────────────┐
        │  Go Action Controller (:8080)│   │  Human Escalation Notifier   │
        │  - Pre-isolation DFIR Dump   │   │  - Slack / Webhook Dispatch  │
        │  - Cilium eBPF Quarantine    │   │  - Dashboard HITL Drawer     │
        │  - Workload Restart / Scale  │   └──────────────────────────────┘
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │  Closed-Loop Verification    │
        │  Poll Pod Readiness (30s)    │
        │  Healthy? Done : Escalate    │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │  Neon PostgreSQL & Audit Log │
        │  5 Normalized DB Tables      │
        └──────────────────────────────┘
```

---

## Target Cloud Layout (AWS EC2 K3s)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      AWS EC2 — t4g.xlarge (ARM64)                      │
│             Ubuntu 24.04 LTS (Kernel 6.8+ BTF) | K3s Cluster           │
│                                                                        │
│   Google Online Boutique Microservices (11 services)                  │
│     ├── frontend, cartservice, productcatalogservice, ...              │
│     └── Dedicated chaos namespace: aegis-chaos                        │
│                                                                        │
│   Observability Mesh:                                                  │
│     ├── Prometheus (16 scrape targets) + Alertmanager                  │
│     ├── Loki + Promtail daemonset                                      │
│     └── Falco daemonset (modern_ebpf probe tracing syscalls)          │
│                                                                        │
│   Aegis-SRE Core Stack:                                                │
│     ├── Diagnostic Brain API (:8001)                                   │
│     ├── Mission Control Dashboard (:8000, WebSockets)                  │
│     ├── Go Action Controller (:8080, client-go + Cilium dynamic)       │
│     └── Cilium v1.16.6 (TCX mode, zero-trust network policies)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ SSL / TLS
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   Neon Serverless PostgreSQL (AWS us-east-2)           │
│         5 Normalized Tables: incidents, quarantines, audit_logs,        │
│                    restart_events, guardrail_decisions                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Layout

```text
Aegis-SRE/
├── aws/                    # AWS EC2 automation CLI (launch, up, down, destroy, guard)
│   ├── launch.sh           # Provisions t4g.xlarge, Elastic IP, and K3s bootstrap
│   ├── up.sh / down.sh     # Starts/stops instance to eliminate idle compute costs
│   ├── guard.sh            # Budget alarm ($40 cap) & idle shutdown watchdog
│   ├── apply-stack.sh      # Deploys Cilium, sensors, Online Boutique, and Aegis
│   └── push-image.sh       # Multi-arch docker buildx image pipeline
├── controller/             # Go Kubernetes Action Controller (client-go)
│   ├── main.go             # Entrypoint & CLI flag parsing
│   ├── reconciler.go       # Core reconciliation logic
│   ├── quarantine.go       # Idempotent CiliumNetworkPolicy generator & unquarantine
│   ├── safety.go           # Second-layer execution blocklists & validation
│   ├── status.go           # Kubernetes workload readiness polling
│   ├── workload.go         # Workload rollout restarts and replica scaling
│   ├── forensics.go        # Pre-quarantine volatile DFIR snapshot collector
│   ├── exec.go             # In-pod command executor
│   └── server.go           # Internal REST server listening on :8080
├── src/
│   ├── brain/              # Autonomous AI Diagnostic Engine
│   │   ├── api.py          # FastAPI Brain API (:8001) for alert webhooks
│   │   ├── diagnostic.py   # 3-tier LLM engine (Ollama → Groq → Rules)
│   │   ├── collector.py    # Metric serializer with SensorDarkError fail-closed
│   │   ├── remediation.py  # End-to-end process_alert() loop + AlertDebouncer
│   │   ├── rag.py          # TF-IDF vector retrieval engine
│   │   └── models.py       # Pydantic schemas & RFC-1123 name validators
│   ├── guardrails/         # Deterministic Safety Engine
│   │   ├── engine.py       # Zero-bypass safety validator & rate limiter
│   │   └── actions.py      # Action schemas (RESTART, SCALE, QUARANTINE)
│   ├── dashboard/          # Mission Control WebSockets Dashboard (:8000)
│   │   ├── server.py       # FastAPI application entrypoint
│   │   ├── routes.py       # REST API endpoints & incident pagination
│   │   └── state.py        # LiveClusterState real-time cache
│   ├── db/                 # Neon PostgreSQL Persistence
│   │   ├── models.py       # 5 SQLAlchemy ORM models
│   │   └── session.py      # Async session manager with SQLite fallback
│   ├── knowledge_base/     # 12 SRE Runbooks & MITRE ATT&CK reference playbooks
│   └── target_app/         # Flask e-commerce target app for local testing
├── config/                 # Sensor configs (Prometheus, Falco rules, Loki, Grafana)
├── deploy/                 # Docker Compose full local testing stack
├── docs/                   # Academic Capstone Documentation & Synopsis
│   └── PROJECT_SYNOPSIS.md # Complete 1600+ line B.Tech Major Project Report
├── k8s/                    # Kubernetes manifests
│   ├── monitoring/         # Prometheus, Loki, Falco daemonsets
│   ├── online-boutique/    # 11-microservice polyglot target application
│   └── chaos/              # Chaos engineering fault injection manifests
├── test/                   # 18 automated test suites (232 test cases)
└── requirements.txt        # Python production dependencies
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Cloud Infrastructure** | AWS EC2 (`t4g.xlarge` ARM64 / `t3.medium`) | Ubuntu 24.04 LTS host with kernel 6.8+ BTF |
| **Container Orchestration** | K3s v1.31+ | Lightweight production Kubernetes engine |
| **Networking & CNI** | Cilium v1.16.6 (TCX mode) | eBPF zero-trust packet filtering & network policy |
| **Security Sensing** | Falco v0.38+ (`modern_ebpf`) | Kernel syscall tracing for MITRE ATT&CK detection |
| **Metrics Telemetry** | Prometheus + Alertmanager | 16 scrape targets capturing Golden Signals |
| **Log Aggregation** | Grafana Loki + Promtail | Pod stdout/stderr log streaming |
| **AI Diagnosis** | Groq Cloud LPU (`openai/gpt-oss-20b`) | Primary sub-second cognitive root cause analysis |
| **Local LLM Fallback** | Ollama (`llama3.2:3b` / `llama3.1:8b`) | On-node private fallback inference engine |
| **Contextual Memory** | Scikit-learn TF-IDF + Cosine Similarity | Vector retrieval over 12 SRE / MITRE runbooks |
| **Deterministic Guardrails** | Python in-memory validation | Blocklists, confidence floors, workload rate limits |
| **Autonomous Controller** | Go 1.22 (`client-go`) | Pre-quarantine forensics & cluster mutation muscle |
| **Audit & State Store** | Neon Serverless PostgreSQL v18 | 5 normalized tables with multi-AZ durability |
| **Command Center** | FastAPI + WebSockets | Real-time mission control UI with HITL controls |

---

## Service Port Reference

| Service | Port | Protocol | Purpose |
|---|---|---|---|
| **Mission Control Dashboard** | `8000` | HTTP / WS | Web UI, operator HITL drawer, `/ws/telemetry` |
| **Diagnostic Brain API** | `8001` | HTTP | Prometheus & Falco alert ingest, `/api/v1/remediate` |
| **Go Action Controller** | `8080` | HTTP | Internal cluster execution engine (`/api/v1/reconcile`) |
| **Prometheus Server** | `9090` | HTTP | Metrics collection and PromQL querying |
| **Alertmanager** | `9093` | HTTP | Alert routing and webhook dispatch |
| **Grafana** | `3000` | HTTP | Visual operational dashboards (`admin` / `admin`) |
| **Loki** | `3100` | HTTP | Centralized log ingestion and LogQL querying |
| **Target App (Local)** | `5000` | HTTP | Test mock application endpoint |

---

## Quick Start (Local Development)

### 1. Prerequisites
- **Python** 3.10+
- **Docker** and Docker Compose
- **Go** 1.22+ (to build the controller binary)
- **Ollama** (optional for local LLM inference) — [ollama.com](https://ollama.com)

### 2. Environment Setup
```bash
git clone https://github.com/aegis-sre-team/Aegis-SRE.git
cd Aegis-SRE
cp .env.example .env
```

Configure your `.env`:
```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
GROQ_API_KEY=gsk_your_groq_key_here
DATABASE_URL=postgresql+asyncpg://user:pass@ep-cool-db.us-east-2.aws.neon.tech/neondb
```

### 3. Running All Automated Tests (232 Tests)
Run the full automated test battery with 100% pass rate:

```powershell
# Windows PowerShell
$env:PYTHONPATH="."; python -m unittest discover -s test -p "test_*.py"
```

```bash
# Linux / macOS Bash
export PYTHONPATH=.
python -m unittest discover -s test -p "test_*.py"
```

### 4. Running the Stack Locally

**Option A — Launch via Docker Compose:**
```bash
docker compose -f deploy/docker-compose.yml up -d --build
```
Access the dashboard at `http://localhost:8000`.

**Option B — Run Individual Microservices:**
```bash
# Terminal 1: Launch Brain API (:8001)
$env:PYTHONPATH="."; python -m src.brain.api

# Terminal 2: Launch Mission Control Dashboard (:8000)
$env:PYTHONPATH="."; python -m src.dashboard.server

# Terminal 3: Build & Launch Go Controller (:8080)
cd controller
go build -o aegis-controller .
./aegis-controller --kubeconfig=$HOME/.kube/config
```

---

## AWS Cloud Lab Deployment (`aws/`)

The `aws/` directory provides shell CLI automation to provision and operate an isolated EC2 lab environment without requiring complex Terraform state files.

### 1. First-Time Lab Provisioning
```bash
export AWS_REGION=us-east-1
export ALLOWED_CIDRS="$(curl -s https://checkip.amazonaws.com)/32"

# 1. Launch EC2 instance (t4g.xlarge ARM64) and install K3s
aws/launch.sh

# 2. Attach cost & idle guards
aws/guard.sh budget your-email@domain.com 40   # Email alert at $40/month
aws/guard.sh idle-stop                         # Auto-stop if CPU < 10% for 3 hours

# 3. Deploy Cilium, monitoring, Online Boutique, and Aegis stack
BUILD=1 aws/apply-stack.sh
```

### 2. Daily Operations & Cost Control
To prevent incurring unnecessary cloud compute charges, stop the instance when not actively running experiments:

```bash
aws/down.sh      # Stops EC2 compute (disk & Elastic IP preserved, ~$3/mo)
aws/up.sh        # Starts EC2 instance; K3s pods recover automatically in ~60s
aws/destroy.sh   # Tears down all AWS resources, security groups, and Elastic IP
```

---

## Security & MITRE ATT&CK Matrix

Aegis-SRE dynamically maps incoming eBPF kernel security detections directly to MITRE ATT&CK techniques:

| Signal / Falco Event | MITRE ATT&CK Technique | Aegis Autonomous Action | Evidence Preservation |
|---|---|---|---|
| Spawned shell in container | **T1059** (Command Interpreter) | `CILIUM_QUARANTINE_EBPF` | DFIR Process & Log Snapshot captured first |
| Read sensitive file (`/etc/shadow`) | **T1552** (Unsecured Credentials) | `CILIUM_QUARANTINE_EBPF` | Full stdout/stderr + network connections dump |
| Execution of `nmap` / `netcat` | **T1046** (Network Discovery) | `CILIUM_QUARANTINE_EBPF` | Container cgroup isolated via Cilium TCX |
| Unauthorized crontab modification | **T1053** (Scheduled Task/Job) | `CILIUM_QUARANTINE_EBPF` | Cron directory state snapshot captured |
| Outbound traffic to known miner pool | **Resource Hijacking** | `CILIUM_QUARANTINE_EBPF` | Socket table + CPU cgroup throttled |
| OOMKilled alert (rate = 0, no threat) | **Operational Failure** | `RESTART_POD` | Pod restart event logged to PostgreSQL |
| Sustained CPU throttling (no threat) | **Operational Failure** | `SCALE_DEPLOYMENT` | Deployment replica scaled (+1) |

---

## Verification & Test Battery (232 / 232 Passed)

The system includes 18 specialized test suites executed against a mock sensory and cluster environment:

```text
================================================================================
[SUITE 01] test_brain_api.py           ........ [PASSED 8/8]
[SUITE 02] test_chaos_benchmark.py     ........ [PASSED 8/8]
[SUITE 03] test_collector.py           ......... [PASSED 9/9]
[SUITE 04] test_controller.py          .......... [PASSED 10/10]
[SUITE 05] test_dashboard.py           .......  [PASSED 7/7]
[SUITE 06] test_edge_cases.py          ....     [PASSED 4/4]
[SUITE 07] test_executor_controller.py .............. [PASSED 14/14]
[SUITE 08] test_falco_ingest.py        .............. [PASSED 14/14]
[SUITE 09] test_guardrails.py          ........................ [PASSED 24/24]
[SUITE 10] test_hardening.py           ........ [PASSED 8/8]
[SUITE 11] test_ingest_hardening.py    ................ [PASSED 16/16]
[SUITE 12] test_isolation.py           .....    [PASSED 5/5]
[SUITE 13] test_live_state.py          ........................... [PASSED 27/27]
[SUITE 14] test_manifests.py           ............... [PASSED 15/15]
[SUITE 15] test_pipeline.py            ..       [PASSED 2/2]
[SUITE 16] test_remediation_loop.py    ........................ [PASSED 24/24]
[SUITE 17] test_review_round2.py       .................... [PASSED 20/20]
[SUITE 18] test_review_round3.py       ................... [PASSED 17/17]
--------------------------------------------------------------------------------
TOTAL SCORE: 232 / 232 TESTS PASSED (100% SUCCESS RATE)
================================================================================
```

---

## Academic Project Team & Credits

Developed as a Major Capstone Project at **Jaypee Institute of Information Technology, Noida (Academic Session 2026–2027)** under the supervision of **Prof. Prashant Kaushik**:

- **Krish Suri (Enrolment No: 23103121) — 50% Share:** Cloud Infrastructure & Backend Services (AWS EC2, K3s, Cilium CNI, Go Kubernetes Controller, Alertmanager & Slack Escalation, Neon PostgreSQL Schema, FastAPI Dashboard with WebSockets, 3-Tier LLM Client, AWS CLI Automation Suite).
- **Krishna Gupta (Enrolment No: 23103114) — 50% Share:** Security Sensing, Detection & Guardrails (Falco eBPF Kernel Rules, Cilium Quarantine Policy Generator, Prometheus/Loki Monitoring Mesh, Chaos Engineering Suite, SRE Runbooks & TF-IDF RAG, Deterministic Guardrail Engine, AlertDebouncer, Ingest Edge Sanitization, Fail-Closed Fallback Engine).

Complete academic report, literature survey, and PO/PSO mapping are available in [`docs/PROJECT_SYNOPSIS.md`](docs/PROJECT_SYNOPSIS.md).

---

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.
