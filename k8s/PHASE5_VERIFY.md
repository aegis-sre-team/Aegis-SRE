# Phase 5 verify: Go action controller (run on the live cluster)

> **Status:** code, unit tests (40 Go + Python contract tests) and manifests are done offline.
> Everything below is the part that can only be proven on a real cluster. Tick the boxes in `PHASES.md` only after these pass.
>
> Context on AWS: `export KUBECONFIG=~/.kube/aegis-aws.yaml` (context `aegis-aws`). Skip any `use-context oracle-k3s` lines in older docs.

## 0. Deploy

```bash
BUILD=1 aws/apply-stack.sh        # first time: builds both arm64 images and ships them
kubectl -n aegis-system get pods  # aegis-brain and aegis-controller Ready
```

## 1. Controller is up and in dry-run

```bash
kubectl -n aegis-system port-forward svc/aegis-controller 8080:8080 &
TOKEN=$(kubectl -n aegis-system get secret aegis-controller-token -o jsonpath='{.data.token}' | base64 -d)
curl -s localhost:8080/healthz
# expect: "dry_run":true, "cluster_connected":true
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/api/v1/reconcile   # expect 401 (no token)
```

## 2. Safety (still dry-run, nothing can change)

Pick a real pod: `POD=$(kubectl -n online-boutique get pod -l app=cartservice -o name | head -1 | cut -d/ -f2)`

```bash
call() { curl -s -w ' [%{http_code}]\n' -X POST localhost:8080/api/v1/reconcile \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$1"; }

call '{"approved":true,"final_action":"RESTART_POD","target_pod":"'$POD'","namespace":"online-boutique"}'   # dry_run success [200]
call '{"approved":false,"final_action":"RESTART_POD","target_pod":"'$POD'","namespace":"online-boutique"}'  # skipped [200]
call '{"approved":true,"final_action":"RESTART_POD","target_pod":"coredns","namespace":"kube-system"}'     # [403]
call '{"approved":true,"final_action":"DELETE_NAMESPACE","target_pod":"x","namespace":"online-boutique"}'  # [400]
call '{"approved":true,"final_action":"RESTART_POD","target_pod":"ghost","namespace":"online-boutique"}'   # [404]
kubectl auth can-i delete pods -n kube-system --as=system:serviceaccount:aegis-system:aegis-controller    # no
kubectl auth can-i delete pods -n online-boutique --as=system:serviceaccount:aegis-system:aegis-controller # yes
```

- [ ] all seven results match the comments

## 3. Go live (deliberate, both switches)

```bash
kubectl -n aegis-system set env deploy/aegis-controller DRY_RUN=false
kubectl -n aegis-system set env deploy/aegis-brain AEGIS_DRY_RUN=false
```

## 4. RESTART rolls a real pod

```bash
call '{"approved":true,"final_action":"RESTART_POD","target_pod":"'$POD'","namespace":"online-boutique"}'
# expect "mode":"k8s_cluster", "workload":"cartservice"
kubectl -n online-boutique rollout status deploy/cartservice
kubectl -n online-boutique get pods -l app=cartservice      # a NEW pod name
curl -s "localhost:8080/api/v1/status?namespace=online-boutique&pod=$POD&deployment=cartservice" -H "Authorization: Bearer $TOKEN"
# expect found:false and deployment desired==ready==updated
```

- [ ] new pod Running/Ready, status call reports the rollout complete

### 4b. Restart refuses pods nothing would recreate

```bash
kubectl -n aegis-chaos run lonely --image=busybox:1.36 --restart=Never -- sleep 3600
call '{"approved":true,"final_action":"RESTART_POD","target_pod":"lonely","namespace":"aegis-chaos"}'   # [422], pod still exists
kubectl -n aegis-chaos get pod lonely && kubectl -n aegis-chaos delete pod lonely
```

- [ ] a bare pod is refused (HTTP 422) and not deleted

## 5. SCALE adds a replica (capped at MAX_REPLICAS=4)

```bash
call '{"approved":true,"final_action":"SCALE_DEPLOYMENT","target_pod":"'$(kubectl -n online-boutique get pod -l app=adservice -o name | head -1 | cut -d/ -f2)'","namespace":"online-boutique"}'
kubectl -n online-boutique get deploy adservice    # replicas +1
```

- [ ] replicas increased by one; repeating until the cap stops at 4

## 6. QUARANTINE isolates and keeps the pod

```bash
kubectl scale deploy/chaos-shell-injection -n aegis-chaos --replicas=1
BAD=$(kubectl -n aegis-chaos get pod -l app=chaos-shell-injection -o name | head -1 | cut -d/ -f2)
BADIP=$(kubectl -n aegis-chaos get pod $BAD -o jsonpath='{.status.podIP}')

# BEFORE: connectivity works (from another pod)
kubectl -n online-boutique run probe --rm -it --restart=Never --image=busybox:1.36 -- wget -qO- -T 3 http://$BADIP:80 ; echo "exit=$?"

call '{"approved":true,"final_action":"CILIUM_QUARANTINE_EBPF","target_pod":"'$BAD'","namespace":"aegis-chaos","mitre_technique":"T1059","reason":"manual verify"}'
```

Expect `status:"success"`, a `policy_name`, and a `forensics` object with real `events`, `logs`, `phase`, `node_name`, `pod_ip` (and `process_list` if the image has `ps`).

```bash
kubectl -n aegis-chaos get ciliumnetworkpolicy                              # aegis-quarantine-<pod>
kubectl -n aegis-chaos get pod $BAD -L aegis.io/quarantine-target           # label present, pod still Running
kubectl -n aegis-chaos get ciliumnetworkpolicy aegis-quarantine-$BAD -o yaml | grep -i -A3 'status\|valid'   # must NOT say invalid
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium policy get | grep -i quarantine
# AFTER: traffic blocked in both directions
kubectl -n online-boutique run probe --rm -it --restart=Never --image=busybox:1.36 -- wget -qO- -T 3 http://$BADIP:80 ; echo "exit=$?"   # times out / non-zero
kubectl -n aegis-chaos exec $BAD -- wget -qO- -T 3 http://example.com ; echo "exit=$?"                                                     # fails
```

- [ ] pod still exists (state preserved for DFIR) and was Running after the call
- [ ] inbound probe fails after, succeeded before
- [ ] outbound request from the pod fails
- [ ] policy accepted by Cilium (this is the assumption offline tests cannot prove)

**If the policy is rejected or traffic is not blocked:** the Cilium deny-rule syntax in `buildQuarantinePolicy` (`controller/quarantine.go`) and `generate_cilium_quarantine_policy` (`src/controller/cilium_policy.py`) is the first suspect. Check `cilium version` against 1.16 and the CNP status, adjust both places together, and keep `TestQuarantineCreatesDenyPolicyAndLabelsPod` and `test_policy_uses_deny_rules_not_empty_lists` in sync.

## 7. Idempotency and release

```bash
call '{"approved":true,"final_action":"CILIUM_QUARANTINE_EBPF","target_pod":"'$BAD'","namespace":"aegis-chaos"}'   # second call: still success, still ONE policy
kubectl -n aegis-chaos get ciliumnetworkpolicy | grep -c quarantine                                                  # 1
call '{"approved":true,"final_action":"UNQUARANTINE_POD","target_pod":"'$BAD'","namespace":"aegis-chaos"}'
kubectl -n aegis-chaos get pod $BAD -L aegis.io/quarantine-target      # label gone
# probe from step 6 succeeds again
```

- [ ] second quarantine is a no-op success; release removes policy + label; traffic restored

## 8. Audit

- [ ] `controller` logs show each action (`kubectl -n aegis-system logs deploy/aegis-controller`)
- [ ] brain audit rows exist (`GET /api/v1/db/audit` on the dashboard, or the `audit_log` table in the database)

## 9. Put it back

```bash
kubectl -n aegis-system set env deploy/aegis-controller DRY_RUN=true
kubectl -n aegis-system set env deploy/aegis-brain AEGIS_DRY_RUN=true
kubectl scale deploy/chaos-shell-injection -n aegis-chaos --replicas=0
```

## Added after the second review

- [ ] `curl .../api/v1/status?namespace=...&pod=<a pod being deleted>` reports `"terminating": true` during its grace period, and verification after a StatefulSet pod restart waits for the REPLACEMENT to be Ready (the old pod must not count)
- [ ] `call '{"approved":true,"final_action":"SCALE_DEPLOYMENT","target_pod":"'$POD'","namespace":"online-boutique","replicas":0}'` answers HTTP 400 and the Deployment is unchanged
- [ ] quarantine the same pod twice: the second call says `already quarantined`, and `logs/forensics_<pod>.json` on the brain still holds the FIRST snapshot (a later capture, if any, is in a timestamped file next to it)
