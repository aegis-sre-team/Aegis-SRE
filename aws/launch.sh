#!/usr/bin/env bash
# Create the Aegis node on AWS: key pair, security group, Elastic IP, EC2
# instance. Safe to re-run: it refuses to create a second node.
#
# Optional environment:
#   ALLOWED_CIDRS      comma-separated CIDRs allowed to reach SSH (22) and the
#                      K3s API (6443). Default: your current public IP /32.
#                      Include everyone who needs access, e.g.
#                      "203.0.113.5/32,198.51.100.7/32".
#   EXTRA_PUBKEY_FILE  a teammate's public key (.pub) to authorise on the node
#   SPOT=1             run as a persistent Spot instance (stops, not
#                      terminates, when AWS reclaims capacity)
#   INSTANCE_TYPE      default t4g.xlarge; VOLUME_GB default 60
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

require_aws

[ -z "$(find_instance)" ] || die "An Aegis instance already exists. Use up.sh / down.sh, or destroy.sh first."

# --- who may connect -------------------------------------------------------
if [ -z "${ALLOWED_CIDRS:-}" ]; then
  need curl
  my_ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
  [ -n "$my_ip" ] || die "Could not detect your public IP; set ALLOWED_CIDRS."
  ALLOWED_CIDRS="$my_ip/32"
  warn "ALLOWED_CIDRS not set; allowing only this machine ($ALLOWED_CIDRS)."
  warn "Anyone else (e.g. the person who will run kubectl) must be added: re-run with ALLOWED_CIDRS=..."
fi
IFS=',' read -r -a CIDRS <<< "$ALLOWED_CIDRS"

# --- key pair --------------------------------------------------------------
if aws ec2 describe-key-pairs --key-names "$KEY_NAME" >/dev/null 2>&1; then
  [ -f "$KEY_FILE" ] || die "Key pair '$KEY_NAME' exists in AWS but $KEY_FILE is missing. Delete the key pair or set KEY_FILE."
  log "Key pair '$KEY_NAME' already exists."
else
  log "Creating key pair '$KEY_NAME' -> $KEY_FILE"
  mkdir -p "$(dirname "$KEY_FILE")"
  ( umask 077
    aws ec2 create-key-pair --key-name "$KEY_NAME" --key-type ed25519 \
      --tag-specifications "ResourceType=key-pair,Tags=[{Key=Project,Value=$PROJECT_TAG}]" \
      --query KeyMaterial --output text > "$KEY_FILE" )
  chmod 600 "$KEY_FILE"
fi

# --- security group (default VPC) -----------------------------------------
vpc_id="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
case "$vpc_id" in ""|None) die "No default VPC in this region. Create one with 'aws ec2 create-default-vpc'." ;; esac

sg_id="$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$vpc_id" \
  --query 'SecurityGroups[0].GroupId' --output text)"
case "$sg_id" in
  ""|None)
    log "Creating security group '$SG_NAME'"
    sg_id="$(aws ec2 create-security-group --group-name "$SG_NAME" \
      --description "Aegis-SRE: SSH and K3s API from allowed CIDRs only" --vpc-id "$vpc_id" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=$PROJECT_TAG}]" \
      --query GroupId --output text)"
    ;;
  *) log "Security group '$SG_NAME' already exists ($sg_id)." ;;
esac
for cidr in "${CIDRS[@]}"; do
  for port in 22 6443; do
    # A duplicate rule is an error we can ignore.
    aws ec2 authorize-security-group-ingress --group-id "$sg_id" \
      --protocol tcp --port "$port" --cidr "$cidr" >/dev/null 2>&1 || true
  done
done

# --- Elastic IP (stable address across stop/start) -------------------------
eip="$(find_eip)"
if [ -z "$eip" ]; then
  log "Allocating Elastic IP"
  alloc_id="$(aws ec2 allocate-address --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Project,Value=$PROJECT_TAG}]" \
    --query AllocationId --output text)"
  public_ip="$(aws ec2 describe-addresses --allocation-ids "$alloc_id" --query 'Addresses[0].PublicIp' --output text)"
else
  alloc_id="${eip%%[[:space:]]*}"; public_ip="${eip##*[[:space:]]}"
  log "Reusing Elastic IP $public_ip"
fi

# --- AMI + user-data -------------------------------------------------------
ami_id="$(aws ssm get-parameter \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)"

userdata="$(mktemp)"
trap 'rm -f "$userdata"' EXIT
{
  echo '#!/bin/bash'
  printf 'export AEGIS_PUBLIC_IP=%q\n' "$public_ip"
  if [ -n "${EXTRA_PUBKEY_FILE:-}" ]; then
    [ -f "$EXTRA_PUBKEY_FILE" ] || die "EXTRA_PUBKEY_FILE not found: $EXTRA_PUBKEY_FILE"
    printf 'export AEGIS_EXTRA_SSH_KEY=%q\n' "$(cat "$EXTRA_PUBKEY_FILE")"
  fi
  [ -z "${K3S_VERSION:-}" ] || printf 'export K3S_VERSION=%q\n' "$K3S_VERSION"
  tail -n +2 "$HERE/bootstrap.sh"   # drop bootstrap's own shebang
} > "$userdata"

# --- run it ----------------------------------------------------------------
# Burstable (t*) instances default to "unlimited" credits, which bills extra when
# CPU runs hot (chaos + Falco + Prometheus). "standard" throttles instead.
credit_args=()
case "$INSTANCE_TYPE" in t*) credit_args=(--credit-specification CpuCredits=standard) ;; esac

market_args=()
if [ "${SPOT:-0}" = "1" ]; then
  log "Requesting persistent Spot capacity (interruption behaviour: stop)"
  market_args=(--instance-market-options \
    'MarketType=spot,SpotOptions={SpotInstanceType=persistent,InstanceInterruptionBehavior=stop}')
fi

log "Launching $INSTANCE_TYPE ($ami_id), ${VOLUME_GB} GB gp3"
instance_id="$(aws ec2 run-instances \
  --image-id "$ami_id" --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" --security-group-ids "$sg_id" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$VOLUME_GB,VolumeType=gp3,DeleteOnTermination=true}" \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --user-data "file://$userdata" \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Project,Value=$PROJECT_TAG},{Key=Name,Value=$PROJECT_TAG}]" \
    "ResourceType=volume,Tags=[{Key=Project,Value=$PROJECT_TAG}]" \
  ${credit_args[@]+"${credit_args[@]}"}   ${market_args[@]+"${market_args[@]}"} \
  --query 'Instances[0].InstanceId' --output text)"

log "Waiting for $instance_id to run"
aws ec2 wait instance-running --instance-ids "$instance_id"
aws ec2 associate-address --instance-id "$instance_id" --allocation-id "$alloc_id" >/dev/null

cat <<EOF

Instance : $instance_id
Address  : $public_ip
SSH key  : $KEY_FILE

Bootstrap (K3s install) takes ~2-3 minutes. Watch it:
  ssh -i $KEY_FILE $SSH_USER@$public_ip 'tail -f /var/log/aegis-bootstrap.log'

When it prints "bootstrap done", install Cilium and the workloads:
  aws/apply-stack.sh

Recommended next: aws/guard.sh budget <email> <usd>   and   aws/guard.sh idle-stop
EOF
