package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// ActionReconciler executes guardrail-approved actions on the cluster.
type ActionReconciler struct {
	KubeClient        kubernetes.Interface
	DynamicClient     dynamic.Interface
	DryRun            bool            // when true nothing is mutated; defaults to true (safe)
	MaxReplicas       int32           // upper bound for SCALE_DEPLOYMENT (default 4)
	AllowedNamespaces map[string]bool // optional allowlist; empty = any non-protected namespace
	Exec              ExecFunc        // optional; used for best-effort process lists in forensics
	ChaosEnabled      bool            // chaos start/stop API; off unless CHAOS_ENABLED=true, independent of DryRun
	Now               func() time.Time
}

func NewActionReconciler(client kubernetes.Interface, dynClient dynamic.Interface) *ActionReconciler {
	return &ActionReconciler{KubeClient: client, DynamicClient: dynClient, DryRun: true, MaxReplicas: 4}
}

func (r *ActionReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile validates and executes one request. Safety checks run before any cluster call.
func (r *ActionReconciler) Reconcile(ctx context.Context, req ActionRequest) (ActionResult, error) {
	base := ActionResult{Action: req.FinalAction, Target: req.TargetPod, Namespace: req.Namespace, Status: "error"}

	if err := validateRequest(req, r.AllowedNamespaces); err != nil {
		return base, err
	}
	if req.FinalAction == "ESCALATE" {
		log.Printf("[ESCALATE] pod %s/%s escalated to a human operator (no cluster change)", req.Namespace, req.TargetPod)
		base.Status, base.Mode, base.Message = "success", "none", "escalated to human operator; no cluster change"
		return base, nil
	}
	if r.DryRun || r.KubeClient == nil {
		return r.dryRun(ctx, req, base)
	}

	log.Printf("[EXECUTE] %s on %s/%s (reason: %s)", req.FinalAction, req.Namespace, req.TargetPod, req.Reason)
	switch req.FinalAction {
	case "RESTART_POD":
		return r.restart(ctx, req, base)
	case "SCALE_DEPLOYMENT":
		return r.scale(ctx, req, base)
	case "CILIUM_QUARANTINE_EBPF":
		return r.quarantine(ctx, req, base)
	case "UNQUARANTINE_POD":
		return r.unquarantine(ctx, req, base)
	}
	return base, fmt.Errorf("%w: %q", ErrUnsupportedAction, req.FinalAction)
}

// dryRun reports what would happen. It only reads (to prove the target exists); it never mutates.
func (r *ActionReconciler) dryRun(ctx context.Context, req ActionRequest, base ActionResult) (ActionResult, error) {
	base.Mode = "dry_run"
	if r.KubeClient != nil && req.FinalAction != "UNQUARANTINE_POD" {
		if _, err := r.resolveWorkload(ctx, req.Namespace, req.TargetPod); err != nil {
			return base, err
		}
	}
	base.Status = "success"
	base.Message = fmt.Sprintf("[DRY_RUN] would execute %s on %s/%s; no cluster change made", req.FinalAction, req.Namespace, req.TargetPod)
	return base, nil
}
