#!/usr/bin/env bash
# Run from a workstation (needs kubectl, helm, ssh) after bootstrap finished.
# Fetches the kubeconfig, installs Cilium, then applies the Aegis stack in the
# order PHASES.md documents.
#
#   aws/apply-stack.sh                full stack
#   SKIP_BRAIN=1 aws/apply-stack.sh   sensors + Boutique (+ controller) only
#   SKIP_CONTROLLER=1 aws/apply-stack.sh   do not deploy the Go controller
#   WITH_GRAFANA=1 aws/apply-stack.sh also deploy Grafana (off by default: nothing in
#                                     the pipeline reads it; saves RAM)
#   AEGIS_HOST=<ip> ...               skip the AWS lookup (no AWS credentials needed)
#   KUBE_API_HOST=127.0.0.1 ...       reach the API through an SSH tunnel instead of port 6443:
#                                     ssh -N -L 6443:127.0.0.1:6443 ubuntu@<ip>
#   PLATFORM=linux/amd64 BUILD=1 ...  build images for an x86 node (default linux/arm64)
#
# Chaos pods are NOT applied; PHASES.md has you trigger them one at a time:
#   kubectl apply -f k8s/chaos/chaos-cpu-spike.yaml
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

need kubectl; need helm; need ssh
CILIUM_VERSION="${CILIUM_VERSION:-1.16.6}"   # pinned to what INSTALL.md validated
KUBECONFIG_OUT="${KUBECONFIG_OUT:-$HOME/.kube/aegis-aws.yaml}"
host="$(node_host)"

# --- 1. kubeconfig ---------------------------------------------------------
log "Waiting for bootstrap on $host"
for _ in $(seq 1 60); do
  if ssh_node 'test -f /var/lib/aegis/bootstrap.done' 2>/dev/null; then break; fi
  sleep 5
done
ssh_node 'test -f /var/lib/aegis/bootstrap.done' 2>/dev/null \
  || die "Bootstrap has not finished. On the node: tail /var/log/aegis-bootstrap.log"

log "Fetching kubeconfig -> $KUBECONFIG_OUT"
mkdir -p "$(dirname "$KUBECONFIG_OUT")"
( umask 077
  ssh_node 'sudo cat /etc/rancher/k3s/k3s.yaml' \
    | sed -E "s#https://127\.0\.0\.1:6443#https://${KUBE_API_HOST:-$host}:6443#; s#^([[:space:]]*(- )?)(name|cluster|user|current-context): default\$#\1\3: aegis-aws#" \
    > "$KUBECONFIG_OUT" )
export KUBECONFIG="$KUBECONFIG_OUT"
kubectl get nodes >/dev/null || die "Cannot reach the API at $host:6443. Is your IP in ALLOWED_CIDRS?"

# --- 2. Cilium (Path A in k8s/cilium/INSTALL.md) ---------------------------
node_ip="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
log "Installing Cilium $CILIUM_VERSION (k8sServiceHost=$node_ip)"
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
helm upgrade --install cilium cilium/cilium \
  --namespace kube-system --version "$CILIUM_VERSION" \
  -f "$ROOT/k8s/cilium/values-k3s.yaml" \
  --set k8sServiceHost="$node_ip" --set k8sServicePort=6443 \
  --wait --timeout 10m
kubectl wait --for=condition=Ready node --all --timeout=5m

# --- 3. Workloads (order from PHASES.md) -----------------------------------
cd "$ROOT"
log "Applying namespaces, Online Boutique, monitoring"
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/online-boutique/online-boutique.yaml
kubectl scale deploy/loadgenerator -n online-boutique --replicas=0 2>/dev/null || true
for f in prometheus alertmanager loki promtail falco; do
  kubectl apply -f "k8s/monitoring/$f.yaml"
done
[ "${WITH_GRAFANA:-0}" != "1" ] || kubectl apply -f k8s/monitoring/grafana.yaml

# --- 4. Go controller (the only component allowed to change the cluster) ----
if [ "${SKIP_CONTROLLER:-0}" = "1" ]; then
  warn "SKIP_CONTROLLER=1: controller not deployed; the brain cannot execute actions."
else
  if ! kubectl -n aegis-system get secret aegis-controller-token >/dev/null 2>&1; then
    log "Creating aegis-controller-token (random, stored only in the cluster)"
    # --from-literal rather than /dev/stdin so it also works with a Windows kubectl.exe under Git Bash.
    kubectl -n aegis-system create secret generic aegis-controller-token \
      --from-literal=token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" >/dev/null
  fi
  "$HERE/push-image.sh" controller
  kubectl apply -f k8s/controller/controller.yaml
  kubectl -n aegis-system rollout status deploy/aegis-controller --timeout=5m
fi

# --- 5. Brain --------------------------------------------------------------
if [ "${SKIP_BRAIN:-0}" = "1" ]; then
  warn "SKIP_BRAIN=1: brain, its secrets and the AlertManager webhook target are not deployed."
else
  # Read only the three keys we need from .env; never `source` it.
  envfile="$ROOT/.env"
  [ -f "$envfile" ] || die ".env not found. Create it from .env.example (needs DATABASE_URL; GROQ_API_KEY optional) or use SKIP_BRAIN=1."
  get_env() { grep -E "^$1=" "$envfile" | tail -1 | cut -d= -f2- | sed -E "s/^['\"]//; s/['\"]\$//" || true; }
  secrets="$(mktemp)"; trap 'rm -f "$secrets"' EXIT; chmod 600 "$secrets"
  for k in GROQ_API_KEY GROQ_MODEL DATABASE_URL; do
    v="$(get_env "$k")"
    [ -z "$v" ] || printf '%s=%s\n' "$k" "$v" >> "$secrets"
  done
  [ -s "$secrets" ] || warn "No GROQ_API_KEY / DATABASE_URL in .env: brain falls back to rules + SQLite (ephemeral)."
  log "Creating aegis-brain-secrets"
  kubectl -n aegis-system create secret generic aegis-brain-secrets \
    --from-env-file="$secrets" --dry-run=client -o yaml | kubectl apply -f -

  "$HERE/push-image.sh" brain
  kubectl apply -f k8s/brain/brain.yaml
  kubectl -n aegis-system rollout status deploy/aegis-brain --timeout=5m
fi

cat <<EOF

Done. Use this cluster with:
  export KUBECONFIG=$KUBECONFIG_OUT
Verify (k8s/PHASE2_VERIFY.md, k8s/PHASE3_VERIFY.md):
  kubectl get pods -A
  kubectl exec -n kube-system ds/cilium -c cilium-agent -- cilium status --brief
EOF
