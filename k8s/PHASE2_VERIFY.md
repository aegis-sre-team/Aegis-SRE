# Phase 2 verify checklist (oracle-k3s)

```bash
kubectl config use-context oracle-k3s

# Apply order
kubectl apply -f k8s/monitoring/prometheus.yaml
kubectl apply -f k8s/monitoring/alertmanager.yaml
kubectl apply -f k8s/monitoring/loki.yaml
kubectl apply -f k8s/monitoring/promtail.yaml
kubectl apply -f k8s/monitoring/falco.yaml
kubectl apply -f k8s/monitoring/grafana.yaml
# Cilium: follow k8s/cilium/INSTALL.md (Path A preferred)
```

## Checks

| Check | Command / expectation |
|---|---|
| Sensors Running | `kubectl get pods -n monitoring` — prometheus, alertmanager, loki, promtail, falco, grafana Ready |
| Boutique metrics | `kubectl exec -n monitoring deploy/prometheus -- wget -qO- 'http://localhost:9090/api/v1/query?query=count(container_cpu_usage_seconds_total{namespace="online-boutique"})'` → result > 0 |
| CPU alert fires | Scale `chaos-cpu-spike` to 1; wait ~2–3m; Prometheus `/api/v1/alerts` or AlertManager `/api/v2/alerts` shows `AegisHighPodCPU` |
| Promtail labels | Loki `{namespace="online-boutique"}` returns log lines |
| Falco → Loki | Scale `chaos-shell-injection` to 1; Loki `{app="falco"}` contains `SECURITY_ALERT` / `T1059` |
| Cilium | `kubectl api-resources \| grep cilium` and cilium agent Ready (see INSTALL.md) |

Scale chaos back down when done:

```bash
kubectl scale deploy -n aegis-chaos --all --replicas=0
```

**Falco Loki label:** pod label `app=falco` → LogQL `{app="falco"}` (matches `src/brain/collector.py`).

## Added after the review (re-check on the AWS cluster)

- [ ] `kubernetes-cadvisor` target is UP **with TLS verification** (`insecure_skip_verify` was removed)
- [ ] `AegisContainerOOMKilled` and `AegisPodCrashLooping` appear under Alerts (`/rules`) alongside `AegisHighPodCPU`
- [ ] Falco `Aegis Sensitive File Read` triggers on `/etc/shadow` but not on `/etc/passwd`
