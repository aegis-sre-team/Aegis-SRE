# Aegis-SRE on AWS

One EC2 node running K3s + Cilium + the whole Aegis stack, driven by the AWS CLI.
No Terraform: resources are found by the tag `Project=aegis-sre`, so there is no state file to lose.

**Status: untested against a real AWS account.** The scripts pass `bash -n` only. The first run is the real test, so expect to fix small things. Please send back any error you hit.

## Sizing and cost

| | |
|---|---|
| Instance | `t4g.xlarge` (Graviton ARM, 4 vCPU, 16 GB) |
| Disk | 60 GB gp3 |
| OS | Ubuntu 24.04 ARM64 (AWS kernel has BTF, which Falco's `modern_ebpf` needs) |
| Expected footprint | ~8-10 GB RAM (estimate; Grafana is off by default) |

Approximate prices from memory (check the AWS pricing page): about $0.13/hour on-demand, so ~$100/month if left on 24/7.
The intended pattern is **stop it when not in use**: compute billing stops, you keep paying only for the disk and the Elastic IP (a few dollars a month).
`SPOT=1` cuts compute by roughly 60-70% at the price of occasional interruptions.
`t4g` is launched with `CpuCredits=standard`, so sustained CPU throttles instead of billing surplus "unlimited" credits.

The image is arm64, so it must run on Graviton (`t4g`/`m7g`). Do not pick an x86 type.

## What you need (person running the scripts)

- AWS CLI v2, configured (`aws configure`) for an IAM user that can use: EC2, SSM `GetParameter`, CloudWatch alarms, Budgets, STS.
- A default VPC in the chosen region (`aws ec2 create-default-vpc` if missing).
- Bash (Linux, macOS, or Git Bash/WSL on Windows).

Whoever runs `apply-stack.sh` additionally needs `kubectl`, `helm`, `ssh`, and the repo's `.env` (for `DATABASE_URL` and `GROQ_API_KEY`).
If that is a different person from the one with AWS credentials, they only need `AEGIS_HOST=<elastic-ip>` plus the SSH key; no AWS access.

## First-time setup

```bash
export AWS_REGION=<region>

# Everyone who must reach SSH / kubectl, as /32 CIDRs. Do not use 0.0.0.0/0.
export ALLOWED_CIDRS="203.0.113.5/32,198.51.100.7/32"
export EXTRA_PUBKEY_FILE=~/teammate.pub     # optional: gives them SSH too

aws/launch.sh                               # ~1 min; installs K3s in the background (~3 min)
aws/guard.sh budget you@example.com 40      # email alert at 80% / 100% of $40 per month
aws/guard.sh idle-stop                      # auto-stop after 3h under 10% CPU (tune later)

aws/apply-stack.sh                          # Cilium + sensors + Boutique + brain
```

The launcher saves the SSH key to `~/.ssh/aegis-sre-aws.pem`. Hand it to anyone who will run `apply-stack.sh`, or use `EXTRA_PUBKEY_FILE`.

## Daily use

```bash
aws/up.sh        # start the node and wait for SSH
aws/down.sh      # stop it (do this when you finish)
aws/destroy.sh   # delete everything (asks you to type 'destroy')
```

The Elastic IP stays the same across stop/start, so the kubeconfig keeps working.
After `up.sh`, give K3s about a minute; pods come back on their own.

## First deploy and updating images

The first `apply-stack.sh` needs the arm64 images built (Docker Desktop with buildx on the machine running it):

```bash
BUILD=1 aws/apply-stack.sh                   # builds brain + controller images, ships them, applies everything
```

Later, after changing code:

```bash
BUILD=1 aws/push-image.sh brain              # or: controller
kubectl -n aegis-system rollout restart deploy/aegis-brain      # or: deploy/aegis-controller
```

Live actions need two deliberate switches (both default to dry-run): `DRY_RUN=false` on the controller and `AEGIS_DRY_RUN=false` on the brain. See `k8s/PHASE5_VERIFY.md`.

There is no container registry; the image travels as a tarball over SSH.
`aegis-brain-phase3.tar` in the repo root may be stale, so rebuild after changing `src/`.

## Verify

`apply-stack.sh` prints the commands. The full checklists are `k8s/PHASE2_VERIFY.md` and `k8s/PHASE3_VERIFY.md`. Things specific to the AWS move:

- `cilium status --brief` reports OK and `CiliumNetworkPolicy` exists.
- Falco pod is Running (if it crash-loops, check `/sys/kernel/btf/vmlinux` on the node).
- Falco events reach Loki: `{app="falco"}` contains lines after you apply `k8s/chaos/chaos-shell-injection.yaml`.
- Boutique and chaos pods have `CiliumEndpoint` entries (`kubectl get ciliumendpoints -A`).

## Known limits / gotchas

- **Idle-stop threshold is a guess.** Check the node's real idle CPU in CloudWatch after the first session, then re-run `guard.sh idle-stop <pct>`. The alarm is tied to the instance id, so re-run it after any destroy + launch.
- **The budget covers the whole AWS account**, not only Aegis.
- **Your IP changes?** Add the new CIDR to the security group in the console (ports 22 and 6443), or re-run `launch.sh` after destroying.
- **Dashboard/brain access:** nothing is exposed publicly. Use `kubectl port-forward` or the Cloudflare tunnel scripts in `scripts/`.
- **K3s version is a guess.** The repo never recorded what ran on Oracle, so the node installs the K3s `v1.30` channel (Cilium 1.16 supports Kubernetes up to 1.31). Override with `K3S_VERSION=v1.30.x+k3s1` at launch.
- **Bootstrap seems stuck or failed?** Re-run it by hand on the node: `sudo bash /var/lib/cloud/instance/scripts/part-001` (it is idempotent once `bootstrap.done` exists).
- **Old docs say `oracle-k3s`.** `PHASES.md` and `k8s/PHASE*_VERIFY.md` start with `kubectl config use-context oracle-k3s`. On AWS use `export KUBECONFIG=~/.kube/aegis-aws.yaml` and skip that line (the context is `aegis-aws`).
- K3s keeps Traefik and the service load balancer at their defaults, as on the Oracle cluster.
