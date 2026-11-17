#!/usr/bin/env bash
# Shared helpers for the aws/ scripts. Source this file; do not run it.
#
# Resources are found by the tag Project=$PROJECT_TAG, so there is no state
# file to lose. If you lose your laptop, `aws ec2 describe-instances` still
# shows everything that belongs to Aegis.

set -euo pipefail

PROJECT_TAG="${PROJECT_TAG:-aegis-sre}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t4g.xlarge}"   # Graviton ARM, 4 vCPU / 16 GB
VOLUME_GB="${VOLUME_GB:-60}"
KEY_NAME="${KEY_NAME:-aegis-sre}"
KEY_FILE="${KEY_FILE:-$HOME/.ssh/aegis-sre-aws.pem}"
SG_NAME="${SG_NAME:-aegis-sre-sg}"
SSH_USER="${SSH_USER:-ubuntu}"
export AWS_PAGER=""

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."; }

# Resolve the region once. Order: AWS_REGION, AWS_DEFAULT_REGION, `aws configure`.
require_aws() {
  need aws
  local region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  [ -n "$region" ] || region="$(aws configure get region 2>/dev/null || true)"
  [ -n "$region" ] || die "No region set. Run 'aws configure' or export AWS_REGION=<region>."
  export AWS_DEFAULT_REGION="$region"
  aws sts get-caller-identity >/dev/null 2>&1 \
    || die "AWS credentials are missing or invalid. Run 'aws configure'."
}

# Prints the instance id of the Aegis node (any live state), or nothing.
find_instance() {
  local id
  id="$(aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text)"
  # `--output text` yields an empty line or "None" when nothing matches.
  case "$id" in ""|None) return 0 ;; esac
  echo "${id%%[[:space:]]*}"
}

instance_state() {
  aws ec2 describe-instances --instance-ids "$1" \
    --query 'Reservations[0].Instances[0].State.Name' --output text
}

# Prints "<allocation-id> <public-ip>" for the tagged Elastic IP, or nothing.
find_eip() {
  local out
  out="$(aws ec2 describe-addresses \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
    --query 'Addresses[0].[AllocationId,PublicIp]' --output text)"
  case "$out" in ""|None*) return 0 ;; esac
  echo "$out"
}

# Node address for SSH/kubectl. AEGIS_HOST lets someone without AWS
# credentials (e.g. a teammate) skip the AWS lookup entirely.
node_host() {
  if [ -n "${AEGIS_HOST:-}" ]; then
    echo "$AEGIS_HOST"
    return
  fi
  require_aws
  local eip
  eip="$(find_eip)"
  [ -n "$eip" ] || die "No Elastic IP found. Run aws/launch.sh first, or set AEGIS_HOST=<ip>."
  echo "${eip##*[[:space:]]}"
}

ssh_key() { echo "${SSH_KEY:-$KEY_FILE}"; }

ssh_node() {
  local host key
  host="$(node_host)"
  key="$(ssh_key)"
  [ -f "$key" ] || die "SSH key not found at $key (set SSH_KEY=<path>)."
  ssh -i "$key" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
      "$SSH_USER@$host" "$@"
}
