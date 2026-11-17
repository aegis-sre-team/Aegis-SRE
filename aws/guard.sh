#!/usr/bin/env bash
# Cost guardrails.
#
#   guard.sh budget <email> <monthly-usd>   email alerts at 80% and 100% of a monthly budget
#   guard.sh idle-stop [cpu-pct] [hours]    auto-stop the node when average CPU stays below
#                                           cpu-pct (default 10) for `hours` (default 3)
#   guard.sh idle-stop --remove             delete the idle-stop alarm
#
# idle-stop caveat: Prometheus, Falco and K3s themselves use some CPU, so the
# right threshold depends on the real idle baseline. After the first session,
# check the node's CPU in CloudWatch and set the threshold just above it.
# The alarm is tied to the instance id, so re-run it after destroy + launch.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

cmd="${1:-}"
require_aws

case "$cmd" in
  budget)
    email="${2:-}"; limit="${3:-}"
    [ -n "$email" ] && [ -n "$limit" ] || die "usage: guard.sh budget <email> <monthly-usd>"
    case "$limit" in *[!0-9.]*|"") die "monthly-usd must be a number" ;; esac
    account="$(aws sts get-caller-identity --query Account --output text)"
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    cat > "$tmp/budget.json" <<EOF
{
  "BudgetName": "${PROJECT_TAG}-monthly",
  "BudgetType": "COST",
  "TimeUnit": "MONTHLY",
  "BudgetLimit": { "Amount": "$limit", "Unit": "USD" }
}
EOF
    notif() {  # $1 = threshold percent
      cat <<EOF
{
  "Notification": { "NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
                    "Threshold": $1, "ThresholdType": "PERCENTAGE" },
  "Subscribers": [ { "SubscriptionType": "EMAIL", "Address": "$email" } ]
}
EOF
    }
    { echo "["; notif 80; echo ","; notif 100; echo "]"; } > "$tmp/notifs.json"
    aws budgets create-budget --account-id "$account" \
      --budget "file://$tmp/budget.json" \
      --notifications-with-subscribers "file://$tmp/notifs.json"
    log "Budget '${PROJECT_TAG}-monthly' created: \$$limit/month, alerts to $email at 80% and 100%."
    log "Note: this budget covers the whole AWS account, not just Aegis."
    ;;

  idle-stop)
    alarm="${PROJECT_TAG}-idle-stop"
    if [ "${2:-}" = "--remove" ]; then
      aws cloudwatch delete-alarms --alarm-names "$alarm"
      log "Removed alarm $alarm."
      exit 0
    fi
    cpu="${2:-10}"; hours="${3:-3}"
    case "$cpu$hours" in *[!0-9]*|"") die "cpu-pct and hours must be whole numbers" ;; esac
    id="$(find_instance)"
    [ -n "$id" ] || die "No Aegis instance found."
    periods=$(( hours * 12 ))   # 5-minute periods
    aws cloudwatch put-metric-alarm \
      --alarm-name "$alarm" \
      --alarm-description "Stop the Aegis node after ${hours}h below ${cpu}% CPU" \
      --namespace AWS/EC2 --metric-name CPUUtilization \
      --dimensions "Name=InstanceId,Value=$id" \
      --statistic Average --period 300 \
      --evaluation-periods "$periods" --datapoints-to-alarm "$periods" \
      --threshold "$cpu" --comparison-operator LessThanThreshold \
      --treat-missing-data notBreaching \
      --alarm-actions "arn:aws:automate:${AWS_DEFAULT_REGION}:ec2:stop"
    log "Alarm $alarm set: stop $id after ${hours}h below ${cpu}% average CPU."
    ;;

  *) die "usage: guard.sh budget <email> <monthly-usd> | idle-stop [cpu-pct] [hours] | idle-stop --remove" ;;
esac
