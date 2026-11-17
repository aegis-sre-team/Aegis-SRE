#!/usr/bin/env bash
# Stop the Aegis node. Compute billing stops; the disk and Elastic IP remain
# (a few dollars a month) and the cluster state is intact when you run up.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

require_aws
id="$(find_instance)"
[ -n "$id" ] || die "No Aegis instance found."

state="$(instance_state "$id")"
if [ "$state" = "stopped" ]; then
  log "$id is already stopped."
  exit 0
fi
log "Stopping $id"
aws ec2 stop-instances --instance-ids "$id" >/dev/null
aws ec2 wait instance-stopped --instance-ids "$id"
log "Stopped. Run aws/up.sh to resume."
