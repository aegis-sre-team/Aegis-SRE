#!/usr/bin/env bash
# Aegis-SRE node bootstrap. Runs ONCE as root on a fresh Ubuntu 24.04 ARM64
# machine (launch.sh passes it as EC2 user-data). It works on any Ubuntu box,
# so it is not tied to AWS.
#
# What it does: host prep + K3s with Flannel disabled. Cilium and the
# workloads are installed afterwards from a workstation by apply-stack.sh,
# because the Helm values live in the repo, not on the node.
#
# Inputs (exported by launch.sh ahead of this script):
#   AEGIS_PUBLIC_IP       public/Elastic IP, added to the API cert so remote kubectl works
#   AEGIS_EXTRA_SSH_KEY   optional extra public key to authorise for the ubuntu user
#   K3S_VERSION           optional exact version, e.g. v1.30.5+k3s1 (overrides the channel)
#   K3S_CHANNEL           K3s release channel (default v1.30). Pinned because Cilium 1.16
#                         (see apply-stack.sh) supports Kubernetes up to 1.31; the 'stable'
#                         channel can move past that.
set -euo pipefail

LOG=/var/log/aegis-bootstrap.log
exec > >(tee -a "$LOG") 2>&1
echo "=== aegis bootstrap start: $(date -u +%FT%TZ) ==="

if [ -f /var/lib/aegis/bootstrap.done ]; then
  echo "Already bootstrapped; nothing to do."
  exit 0
fi

: "${AEGIS_PUBLIC_IP:?AEGIS_PUBLIC_IP must be set}"

# The Elastic IP is attached just after boot, which swaps the instance's public
# address and can drop in-flight downloads. Wait for it, then retry anything
# that touches the network.
retry() {  # retry <attempts> <cmd...>
  local n="$1" i; shift
  for i in $(seq 1 "$n"); do
    "$@" && return 0
    echo "retry $i/$n failed: $*" >&2; sleep 5
  done
  return 1
}

imds_ip() {
  local tok
  tok="$(curl -fsS -m 3 -X PUT http://169.254.169.254/latest/api/token          -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)" || return 1
  curl -fsS -m 3 -H "X-aws-ec2-metadata-token: $tok"        http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null
}
for _ in $(seq 1 36); do   # up to ~3 min; skipped silently off AWS
  [ "$(imds_ip || true)" = "$AEGIS_PUBLIC_IP" ] && break
  sleep 5
done
[ "$(imds_ip || true)" = "$AEGIS_PUBLIC_IP" ]   || echo "NOTE: Elastic IP not seen on this host (not on AWS, or association is slow); continuing." >&2

export DEBIAN_FRONTEND=noninteractive
retry 5 apt-get update -y
retry 5 apt-get install -y --no-install-recommends curl ca-certificates jq

# Optional extra SSH key (lets a teammate who is not the launcher get in).
if [ -n "${AEGIS_EXTRA_SSH_KEY:-}" ]; then
  install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
  echo "$AEGIS_EXTRA_SSH_KEY" >> /home/ubuntu/.ssh/authorized_keys
  chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
  chmod 600 /home/ubuntu/.ssh/authorized_keys
fi

# Falco's modern_ebpf driver needs kernel BTF. Fail early with a clear message
# rather than letting the Falco pod crash-loop later.
if [ ! -e /sys/kernel/btf/vmlinux ]; then
  echo "WARNING: /sys/kernel/btf/vmlinux missing; Falco modern_ebpf will not load on this kernel." >&2
fi

# K3s config written BEFORE first start, so Flannel is never installed and the
# old "flannel cleanup" jobs are not needed (see k8s/cilium/INSTALL.md Path A).
install -d /etc/rancher/k3s
cat > /etc/rancher/k3s/config.yaml <<EOF
flannel-backend: none
disable-network-policy: true
write-kubeconfig-mode: "0644"
tls-san:
  - ${AEGIS_PUBLIC_IP}
EOF

retry 5 curl -sfL --retry 5 --retry-all-errors -o /tmp/k3s-install.sh https://get.k3s.io
# An explicit K3S_VERSION wins; otherwise the pinned channel (see header).
if [ -n "${K3S_VERSION:-}" ]; then
  export INSTALL_K3S_VERSION="$K3S_VERSION"
else
  export INSTALL_K3S_CHANNEL="${K3S_CHANNEL:-v1.30}"
fi
retry 3 sh /tmp/k3s-install.sh server

# The API answers before any CNI exists; the node stays NotReady until
# apply-stack.sh installs Cilium. That is expected.
for _ in $(seq 1 60); do
  if k3s kubectl get --raw /readyz >/dev/null 2>&1; then break; fi
  sleep 3
done
k3s kubectl get --raw /readyz >/dev/null 2>&1 || { echo "K3s API never became ready" >&2; exit 1; }

install -d /var/lib/aegis
date -u +%FT%TZ > /var/lib/aegis/bootstrap.done
echo "=== aegis bootstrap done: node is waiting for Cilium (run aws/apply-stack.sh) ==="
