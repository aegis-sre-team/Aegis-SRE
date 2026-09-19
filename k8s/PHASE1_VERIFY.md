# Phase 1 — Cloud Handoff Checklist

In-repo Phase 1 manifests are ready. Live validation needs your Oracle K3s (or any K3s) cluster.

## Current blocker

No reachable cluster from this workstation (`kubectl` pointed at a dead localhost API). Provision OCI + K3s first.

## Your steps

1. Follow [PHASE1_CLOUD_SETUP.md](../PHASE1_CLOUD_SETUP.md) Steps 1–5.
2. From repo root, set `KUBECONFIG` to the cloud kubeconfig.
3. Apply Phase 1:

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/online-boutique/online-boutique.yaml
kubectl apply -f k8s/chaos/
```

4. Confirm Boutique:

```bash
kubectl get pods -n online-boutique
```

5. Trigger each chaos Deployment (replicas `0` → `1`), confirm anomaly, then scale all back to `0`:

```bash
kubectl scale deploy -n aegis-chaos --all --replicas=0
```

6. Check every box under **Phase 1 → Success criteria** in [PHASES.md](../PHASES.md).

7. Reply in chat when `kubectl get nodes` works so we can validate together and start Phase 2.

## Manifest inventory (already in repo)

| Path | Role |
|---|---|
| `k8s/00-namespace.yaml` | `aegis-chaos`, `aegis-system` |
| `k8s/online-boutique/online-boutique.yaml` | Target app |
| `k8s/chaos/chaos-oom.yaml` | Memory / OOM |
| `k8s/chaos/chaos-cpu-spike.yaml` | CPU burn |
| `k8s/chaos/chaos-crashloop.yaml` | CrashLoopBackOff |
| `k8s/chaos/chaos-shell-injection.yaml` | Shell / T1059 bait |
| `k8s/chaos/chaos-http-500.yaml` | Frontend load / error paths |

Deprecated: `deploy/k8s/03-chaos/` (do not apply).
