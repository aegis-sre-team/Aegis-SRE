#!/usr/bin/env bash
# Get an arm64 image onto the node. There is no registry: the image is a tarball copied over
# SSH and imported into K3s' containerd.
#
#   aws/push-image.sh [brain|controller]            use the existing tarball (default: brain)
#   BUILD=1 aws/push-image.sh [brain|controller]    rebuild it first (needs Docker with buildx)
#
# Rebuild whenever src/ (brain) or controller/ (controller) changes; a tar in the repo root can
# be stale.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

COMPONENT="${1:-brain}"
case "$COMPONENT" in
  brain)
    TAR="$ROOT/aegis-brain-phase3.tar"; IMAGE="aegis-brain:phase3"
    BUILD_CTX="$ROOT"; DOCKERFILE="$ROOT/Dockerfile.brain" ;;
  controller)
    TAR="$ROOT/aegis-controller-phase5.tar"; IMAGE="aegis-controller:phase5"
    BUILD_CTX="$ROOT/controller"; DOCKERFILE="$ROOT/controller/Dockerfile" ;;
  *) die "usage: push-image.sh [brain|controller]" ;;
esac

if [ "${BUILD:-0}" = "1" ]; then
  need docker
  PLATFORM="${PLATFORM:-linux/arm64}"   # set PLATFORM=linux/amd64 for an x86 node
  log "Building $IMAGE for $PLATFORM"
  docker buildx build --platform "$PLATFORM" -f "$DOCKERFILE" \
      -t "$IMAGE" --output "type=docker,dest=$TAR" "$BUILD_CTX"
fi
[ -f "$TAR" ] || die "$TAR not found. Run with BUILD=1 (needs Docker buildx)."

host="$(node_host)"
key="$(ssh_key)"
[ -f "$key" ] || die "SSH key not found at $key (set SSH_KEY=<path>)."

log "Copying $COMPONENT image to $host ($(du -h "$TAR" | cut -f1))"
scp -i "$key" -o StrictHostKeyChecking=accept-new "$TAR" "$SSH_USER@$host:/tmp/aegis-$COMPONENT.tar"
log "Importing into K3s containerd"
ssh_node "sudo k3s ctr images import /tmp/aegis-$COMPONENT.tar && rm -f /tmp/aegis-$COMPONENT.tar"
log "Image $IMAGE is available on the node."
