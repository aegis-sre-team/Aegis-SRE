#!/usr/bin/env bash
# Delete EVERYTHING launch.sh created: instance + disk, Elastic IP, security
# group, key pair, idle-stop alarm. The cluster's local state is lost; guardrail
# history lives in Neon and is untouched.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

require_aws
echo "This permanently deletes the Aegis node, its disk, Elastic IP, security group and key pair."
read -r -p "Type 'destroy' to continue: " answer
[ "$answer" = "destroy" ] || die "Aborted."

id="$(find_instance)"
if [ -n "$id" ]; then
  # A persistent Spot request outlives the instance and launches a replacement
  # (which keeps billing) unless it is cancelled first.
  spot_req="$(aws ec2 describe-instances --instance-ids "$id"     --query 'Reservations[0].Instances[0].SpotInstanceRequestId' --output text)"
  case "$spot_req" in ""|None) ;; *)
    log "Cancelling Spot request $spot_req"
    aws ec2 cancel-spot-instance-requests --spot-instance-request-ids "$spot_req" >/dev/null ;;
  esac
  log "Terminating $id"
  aws ec2 terminate-instances --instance-ids "$id" >/dev/null
  aws ec2 wait instance-terminated --instance-ids "$id"
fi

aws cloudwatch delete-alarms --alarm-names "${PROJECT_TAG}-idle-stop" >/dev/null 2>&1 || true

eip="$(find_eip)"
if [ -n "$eip" ]; then
  log "Releasing Elastic IP ${eip##*[[:space:]]}"
  aws ec2 release-address --allocation-id "${eip%%[[:space:]]*}" >/dev/null
fi

sg_id="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text)"
case "$sg_id" in
  ""|None) ;;
  *)
    log "Deleting security group $sg_id"
    # The network interface can take a moment to detach (DependencyViolation).
    for _ in $(seq 1 12); do
      aws ec2 delete-security-group --group-id "$sg_id" 2>/dev/null && break
      sleep 5
    done
    aws ec2 describe-security-groups --group-ids "$sg_id" >/dev/null 2>&1       && warn "Security group $sg_id still exists; delete it in the console." || true ;;
esac

if aws ec2 describe-key-pairs --key-names "$KEY_NAME" >/dev/null 2>&1; then
  log "Deleting key pair $KEY_NAME"
  aws ec2 delete-key-pair --key-name "$KEY_NAME"
fi
[ ! -f "$KEY_FILE" ] || warn "Local key file $KEY_FILE left in place; delete it if you no longer need it."
log "Done."
