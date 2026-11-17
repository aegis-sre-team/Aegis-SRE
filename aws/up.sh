#!/usr/bin/env bash
# Start the stopped Aegis node and wait until SSH answers.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

require_aws
id="$(find_instance)"
[ -n "$id" ] || die "No Aegis instance found. Run aws/launch.sh first."

state="$(instance_state "$id")"
case "$state" in
  running)  log "$id is already running." ;;
  stopped)  log "Starting $id"; aws ec2 start-instances --instance-ids "$id" >/dev/null
            aws ec2 wait instance-running --instance-ids "$id" ;;
  *)        die "$id is '$state'; wait for it to settle and retry." ;;
esac

host="$(node_host)"
log "Waiting for SSH on $host"
for _ in $(seq 1 40); do
  if ssh_node true 2>/dev/null; then
    log "Node is up at $host. K3s restarts by itself; the API is usually ready in ~1 min."
    exit 0
  fi
  sleep 5
done
die "SSH did not come up in time. Check the instance in the console."
