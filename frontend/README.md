# Aegis console

The operator UI for Aegis-SRE: React 18 + TypeScript + Vite. It talks to the dashboard server
(`src/dashboard/server.py`, port 8000) over REST and `/ws/telemetry`. The backend is API only and serves no
pages; the UI always runs from Vite on http://localhost:5173.

## Run

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api and /ws to :8000
npm run build        # type-checks and writes frontend/dist; `npm run preview` serves it on :4173
npm test             # unit tests for the chain logic and the live-state reducer
npm run typecheck
```

Start the backend first (from the repo root): `PYTHONPATH=. python -m src.dashboard.server`.
Point the dev server at another host with `AEGIS_API=http://host:8000 npm run dev`.

Opening http://localhost:8000 directly returns a JSON service descriptor (API docs at `/docs`).

## What it shows

| Page | Question it answers |
| --- | --- |
| Overview | Are the sensors honest and alive? Which pods are healthy, caged or waiting on me? |
| Incidents | For one incident: what did Aegis see, decide, get allowed, do, and did it hold? (the five-station chain) |
| Needs a human | What did Aegis refuse to do on its own, and what do I choose? Restart, scale, release or mark handled. |
| Quarantine | Which pods are network-cut, and what do their forensics show? Release is a human act. |
| Audit log | Every executor action, filterable, including skipped and dry-run ones. |
| Simulate | Demo mode only: inject a failure and watch the same chain play out. |

## Honesty rules the UI keeps

These mirror the backend's "honest sensors" goal, so do not weaken them:

- The Overview headline (`src/lib/headline.ts`) only says "Everything is healthy" when a reading exists, every sensor
  answered, nothing waits on a person and no pod is quarantined. Anything else outranks it.
- A metric with no series shows **no data**, never `0%`, and is left out of the sparkline.
- Live versus simulated data is labelled in the status bar and on the Overview. Simulate is hidden in live mode.
- A dry run is shown as **Dry run**, never as "Resolved" or "Healthy". Health is only shown as verified when the action really ran.
- The incident row is written before the guardrails run, so the chain trusts the execution record: a skipped action means the guardrails did not approve it.
- Forensics that were not captured say so (404 in live mode); nothing is invented.
- Mutating calls send `X-Aegis-Token` only when the server asks (`AEGIS_DASHBOARD_TOKEN`). The token is kept in `sessionStorage` for the tab.

## Layout

```
src/api         types and fetch client (payload shapes of src/dashboard/server.py)
src/state       reducer, WebSocket provider with REST fallback, data hook, toasts and token prompt
src/lib         pipeline.ts (incident chain logic), format.ts
src/components  Shell, Chain, Dialog, Forensics, small primitives
src/pages       one file per page; routing is hash-based so no server fallback route is needed
src/styles      app.css (design tokens at the top; light only)
```

## Known limits

- The audit table has no incident id, so an incident is joined to its execution record by pod and time.
- Only the latest 50 incidents and audit rows are served by the API; there is no pagination yet.
- Not yet checked against a live cluster (Phase 7 in `PHASES.md`); everything above was exercised against the demo backend.
