# Cilium on K3s (Phase 2 install path)

> **Why:** Phase 5 quarantine uses `CiliumNetworkPolicy`. Flannel (default K3s CNI) cannot enforce those policies.
>
> **Cluster:** originally `oracle-k3s` (node `aegis-primary-vnic`, now gone). Live install used **Path A** (Flannel disabled → Cilium primary, native routing).
> **On AWS:** `aws/bootstrap.sh` writes the K3s config before first start (no Flannel to clean up) and `aws/apply-stack.sh` runs the Helm install below with the node's real IP. Steps 1–2 are not needed there.

## Prerequisites

- `kubectl` context: `oracle-k3s`
- Helm v3 on the workstation

## Path A — Replace Flannel with Cilium (primary CNI) — DONE on lab

### 1. Disable Flannel on the node

Either SSH and write `/etc/rancher/k3s/config.yaml`, or apply the in-cluster Job:

```bash
kubectl apply -f k8s/cilium/k3s-disable-flannel-job.yaml
# Job writes:
#   flannel-backend: none
#   disable-network-policy: true
# then restarts k3s (API briefly drops)
```

### 2. Clean leftover Flannel/VXLAN devices (if Cilium fails with "address already in use")

```bash
kubectl apply -f k8s/cilium/host-net-cleanup-job.yaml
```

### 3. Install Cilium (native routing — avoids VXLAN conflicts on this single-node ARM box)

```bash
kubectl config use-context oracle-k3s
helm repo add cilium https://helm.cilium.io/
helm repo update

helm upgrade --install cilium cilium/cilium \
  --namespace kube-system \
  --version 1.16.6 \
  -f k8s/cilium/values-k3s.yaml \
  --set k8sServiceHost=10.0.0.21 \
  --set k8sServicePort=6443 \
  --wait --timeout 10m
```

> Set `k8sServiceHost` to the node's InternalIP (`kubectl get nodes -o wide`).

### 4. Restart workloads onto Cilium endpoints

```bash
kubectl rollout restart deploy -n monitoring
kubectl rollout restart deploy -n online-boutique
kubectl rollout restart deploy -n kube-system coredns metrics-server
kubectl scale deploy/loadgenerator -n online-boutique --replicas=0
```

### 5. Verify

```bash
kubectl -n kube-system get pods -l app.kubernetes.io/part-of=cilium
kubectl exec -n kube-system ds/cilium -c cilium-agent -- cilium status --brief   # expect OK
kubectl get ciliumendpoints -A
kubectl api-resources | grep ciliumnetworkpolicies
```

Success: Cilium agent Ready, `cilium status --brief` = OK, `CiliumNetworkPolicy` CRD present, Boutique/chaos pods have `CiliumEndpoint` state `ready`.

---

## Path B — Co-install with Flannel (not recommended on this lab)

Portmap/VXLAN chaining conflicted with Flannel (`cilium_vxlan: address already in use`) and tainted the node. Prefer Path A.

---

## Rollback (emergency)

```bash
helm uninstall cilium -n kube-system
# On node: remove /etc/rancher/k3s/config.yaml and restart k3s so Flannel returns
```

## Phase 5 note

Quarantine will apply `CiliumNetworkPolicy` selecting Boutique / attacker pods by label. Workloads must have Cilium endpoints (restart once after CNI cutover).
