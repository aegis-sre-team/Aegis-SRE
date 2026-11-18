# Live chaos controls: start and stop incidents from the UI

Status: **draft, waiting for approval.** Nothing is built.

## Intent and why

Today a failure is injected on the AWS cluster by typing `kubectl scale` on a laptop. The Simulate page only
works on demo data and says "use kubectl" when the cluster is live. The owner wants incidents that "keep
coming" on the real cluster, switched on and off from the frontend, plus more scenario types, so the whole
pipeline (detect, diagnose, guardrail, act, verify, escalate) can be shown and confirmed live without a terminal.

A second finding belongs in scope. The Review ("needs a human") page is always empty against the live cluster.
It lists `ESCALATED_INCIDENTS`, an in-memory dict in the dashboard process that only the demo simulator fills
(`src/dashboard/server.py`). When the real brain escalates, it appends to `logs/escalations.jsonl` inside its own
pod (lost on restart) and optionally calls a webhook (none configured). A live escalation never reaches the
dashboard, so the human-in-the-loop path cannot be demonstrated or trusted.

## Goals

1. From the UI, start and stop each chaos scenario on the live cluster, see its state, and stop everything.
2. Eight scenarios in total: the existing five plus three new ones (below).
3. Chaos pods stop on their own after a time limit, so a forgotten scenario cannot run for days.
4. Real escalations from the brain appear on the Review page, and resolving one from the UI persists.
5. Everything stays dry-run for remediation. No real restart, scale or quarantine is enabled by this work.

## Non-goals

- No change to the guardrail actions, the LLM prompts, or the quarantine design.
- No arbitrary workload creation. The UI cannot pick a namespace, image or deployment.
- Demo mode keeps its simulator exactly as it is.
- No new cloud resources and no change to the AWS scripts.

## Anti-goals (a failure even if it technically works)

- Anyone with the dashboard token being able to start or stop anything outside the `aegis-chaos` allowlist.
- Starting chaos making the controller less safe: chaos must not depend on or weaken `DRY_RUN`.
- A "needs a human" item that exists only in memory and disappears on a dashboard or pod restart.

## Constraints

- The Go controller is the only component that changes the cluster (project rule). The dashboard must call it,
  never the Kubernetes API.
- The controller's Role in `aegis-chaos` already allows `get/list/update` on deployments (checked in
  `k8s/controller/controller.yaml`), which is enough to set replicas. No ClusterRole and no new RBAC.
- Chaos must work while the controller's `DRY_RUN=true`. `DRY_RUN` means "do not remediate"; chaos is the thing
  being remediated, so it needs its own switch.
- The React frontend exists only in local, unpushed commits plus uncommitted changes in the owner's checkout.
  This work builds on those and must be rebased onto them (see Open items).

## Approaches considered

| | What | Trade-off |
|---|---|---|
| **A (chosen by the owner)** | Controller gets one new, tightly limited endpoint; dashboard proxies to it; UI calls the dashboard | Keeps "controller is the only mutator". Needs Go code, tests, and a controller image rebuild. |
| B | Dashboard talks to Kubernetes directly | Least code, but the laptop would hold cluster credentials and the safety rule is gone. Rejected. |
| C | A separate chaos service in the cluster | Clean separation, but one more thing to build, deploy and secure. Rejected. |

## Design (approach A)

### Scenarios (fixed allowlist, all in `aegis-chaos`, all deployments that rest at 0 replicas)

| Id | Deployment | What it does | Expected outcome |
|---|---|---|---|
| `cpu-spike` | `chaos-cpu-spike` | pins CPU above 70% | scale up |
| `oom` | `chaos-oom` | allocates past its memory limit | restart |
| `crashloop` | `chaos-crashloop` | exits immediately | restart |
| `http-500` | `chaos-http-500` | returns server errors | restart |
| `shell-injection` | `chaos-shell-injection` | spawns a shell (T1059) | quarantine |
| **`credential-read`** (new) | `chaos-credential-read` | repeatedly opens `/etc/shadow` (T1552) | quarantine |
| **`network-recon`** (new) | `chaos-network-recon` | repeatedly runs `nc` against cluster addresses (T1046) | quarantine |
| **`restart-storm`** (new) | `chaos-restart-storm` | starts fine, then fails about 20 s later, every time | a few restarts, then the restart budget is exhausted and a human is needed |

The two security scenarios reuse the existing Falco rules, so no rule changes. `restart-storm` is the deterministic
way to exercise the human path: the existing guardrail allows 3 restarts per workload per hour, and a pod that a
restart cannot fix will hit the limit and escalate. Checked in `src/guardrails/validator.py`: the budget is spent
whenever the caller asks it to (`record=reserve_budget`), regardless of dry-run, and it is keyed per workload so a
deployment's replacement pods share it. It still needs one live confirmation.

### Controller (`controller/`)

- `GET  /api/v1/chaos` returns each scenario with `{id, deployment, replicas, ready, expires_at}`.
- `POST /api/v1/chaos` with `{scenario, state: "on"|"off", ttl_minutes?}`. `scenario` must be a key in the allowlist
  map; anything else is 400. The namespace is hard-coded to `aegis-chaos`.
- Same bearer-token protection as the other routes.
- Gated by a new env `CHAOS_ENABLED` (default **false**). When false the endpoint returns 403 and never touches the
  cluster. It is independent of `DRY_RUN`.
- "on" sets replicas to 1 and writes the annotation `aegis.io/chaos-expires-at`. The default time limit is 30 minutes
  (my call), capped at 120. "off" sets replicas to 0 and removes the annotation. Both are idempotent.
- A small loop in the controller scales expired scenarios back to 0, so the limit survives a dashboard restart.
- Tests with the existing client-go fake clientset: allowlist, unknown scenario, disabled flag, idempotency, expiry.

### Dashboard (`src/dashboard/server.py`)

- `GET  /api/v1/chaos/scenarios` and `POST /api/v1/chaos/scenarios/{id}/{start|stop}`, plus `POST .../stop-all`.
- Live mode only. In demo mode these return 409 and the existing simulator is untouched.
- Behind `AEGIS_DASHBOARD_TOKEN` like the other action endpoints. Unknown ids are rejected before any call.
- Each start and stop is written to the audit trail and shown in the terminal log.

### Escalations (brain + dashboard + DB)

- When `process_alert` escalates, the brain also records it in the shared database (incident status `ESCALATED`,
  with the reason), in addition to the existing notifier.
- In live mode the dashboard builds the Review list from the database, not the in-memory dict. Resolving an item
  sets its status to `RESOLVED` and keeps the existing audit behaviour. Demo mode keeps the dict.
- Result: a real "needs a human" item survives restarts and shows on Review.

### Frontend

- In live mode the Simulate page becomes **Chaos controls**: one card per scenario with its expected outcome, a
  Start/Stop button, live state (Stopped, Starting, Running 1/1, with the time left), and **Stop all**.
- Starting a scenario shows a link to the Incidents page; new incidents already stream in over the WebSocket.
- Demo mode keeps today's page.

### Rollout (what must change on the cluster)

New chaos manifests applied, controller image rebuilt and redeployed with `CHAOS_ENABLED=true` and the same token,
brain image rebuilt. Remediation stays dry-run throughout.

## Left to the builder

Exact manifest contents and images for the three new scenarios, the controller loop interval, UI layout and copy,
test structure, and where the escalation fields live in the schema (reuse `IncidentRecord.status` if it fits).

## Open items

1. The frontend this builds on is unpushed and partly uncommitted in the owner's main checkout (`Simulate.tsx`,
   `Shell.tsx`, `server.py` and others are modified). Building on top of it without committing it first risks painful
   conflicts.
2. `restart-storm` must be confirmed live to escalate after the third restart. If it does not, the fallback is to
   make the escalation come from a failed execution instead.
