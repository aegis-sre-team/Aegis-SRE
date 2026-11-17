# Phase 7 verify: live command center (run against the live cluster)

> **Status:** built and unit-tested offline (`src/dashboard/live_state.py`, `server.py`, `static/app.js`). The UI itself has **not been looked at in a browser yet**; only its JavaScript was syntax-checked. Everything here needs a person, a browser and the AWS cluster.

## How the dashboard decides what to show

| `DASHBOARD_MODE` | Behaviour |
|---|---|
| `auto` (default) | **live** when the Go controller answers `/healthz`, otherwise **demo** |
| `live` | always live; if the controller is down the UI shows the failure, never fake pods |
| `demo` | simulated storefront pods (used for offline demos and tests) |

Every state payload carries `data_source`, and the header shows `DATA: LIVE CLUSTER` or `DATA: DEMO (SIMULATED)`. Pods come from the controller (Kubernetes API); CPU/memory from Prometheus (cAdvisor); a missing number is shown as `n/a`, never a default.

## 0. Run it against the cluster

The dashboard needs to reach the controller and Prometheus. Easiest from your laptop:

```bash
export KUBECONFIG=~/.kube/aegis-aws.yaml
kubectl -n aegis-system port-forward svc/aegis-controller 8080:8080 &
kubectl -n monitoring port-forward svc/prometheus 9090:9090 &
export GO_CONTROLLER_URL=http://localhost:8080/api/v1/reconcile
export GO_CONTROLLER_TOKEN=$(kubectl -n aegis-system get secret aegis-controller-token -o jsonpath='{.data.token}' | base64 -d)
export PROMETHEUS_URL=http://localhost:9090
export DATABASE_URL=<the same Neon URL the brain uses>      # so pipeline events from the brain appear
export DASHBOARD_MODE=live
PYTHONPATH=. python -m src.dashboard.server                  # http://localhost:8000
```

## 1. Honest header and startup log

- [ ] header shows `DATA: LIVE CLUSTER`, `CONTROLLER: REACHABLE`, `PROMETHEUS: REACHABLE`
- [ ] stop the Prometheus port-forward: within a few seconds the pill turns red (`UNREACHABLE`) and CPU/MEM show `n/a` (not 0%, not old values)
- [ ] stop the controller port-forward: pods disappear/an error is shown; the page does **not** fall back to fake storefront pods
- [ ] the startup terminal log lists real sensor results (`... NOT connected: ...` for anything dark)

## 2. Live pod grid

- [ ] the grid lists the real Boutique and chaos pods with their namespaces
- [ ] `kubectl -n aegis-chaos scale deploy/chaos-cpu-spike --replicas=1`: the pod appears within ~2-4 s and its CPU rises over the next minute
- [ ] `kubectl -n online-boutique delete pod <one>`: it flips to DEGRADED/restarts and recovers
- [ ] a quarantined pod (Phase 5/6) shows `QUARANTINED`

## 3. Reasoning and actions stream within seconds

With `AEGIS_AUTO_REMEDIATE=true` on the brain (see `PHASE6_VERIFY.md`):

- [ ] trigger shell chaos; a `PIPELINE` line (`CILIUM_QUARANTINE_EBPF on <pod>: COMPLETED_GO_K8S_CLUSTER ...`) appears in the terminal panel within seconds of the controller acting
- [ ] the same for a restart/scale

(Events come from the shared audit table, so the dashboard and brain must use the same `DATABASE_URL`.)

## 4. Real forensics

- [ ] click Forensics on a quarantined pod: source says `captured from the cluster`, with real Kubernetes events and container log lines
- [ ] click it for a pod that was never quarantined: the modal says `No forensics available` (HTTP 404), not a sample
- [ ] in demo mode the sample is labelled `DEMO SAMPLE (not real evidence)`

## 5. HITL calls the real executor

- [ ] open an escalation, choose Restart: the controller log shows the action and the pod rolls (or, in dry-run, the dry-run reply)
- [ ] with the controller stopped, the drawer shows an error (HTTP 502 `FAILED_CONTROLLER_UNREACHABLE`) instead of "success"
- [ ] Unquarantine removes the policy and label (`kubectl get ciliumnetworkpolicy -n aegis-chaos`)

## 6. Demo-only features stay out of live mode

- [ ] the chaos trigger buttons return HTTP 409 in live mode ("inject chaos with kubectl"); they work in demo mode

## Not covered by any automated test

Layout and visual state of the header pills and pod cards, the post-mortem view with real incident data, and WebSocket behaviour over a slow link.

## Added after the second review

- [ ] with `AEGIS_DASHBOARD_TOKEN` set on the dashboard, the HITL Restart/Unquarantine buttons and the chaos buttons prompt for the token once (then remember it in the browser); wrong token -> the action is refused and the terminal shows the error; read-only views keep working without it
- [ ] two pods with the same name in `online-boutique` and `aegis-chaos` (e.g. start a pod called `web-1` in both) show their OWN CPU/MEM in the grid, not each other's
- [ ] a pod in `online-boutique` whose restart is triggered from the drawer is restarted in `online-boutique` (the drawer sends the pod's namespace); an action on a pod the grid does not know is refused with a clear message
