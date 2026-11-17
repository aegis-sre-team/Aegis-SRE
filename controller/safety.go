package main

import (
	"fmt"
	"strings"
)

// protectedNamespaces are never mutated, whatever the brain asks (defence in depth: the brain's
// guardrails enforce the same list, but this service must not trust its caller).
var protectedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"aegis-system":    true,
	"monitoring":      true,
	"cilium-secrets":  true,
}

var supportedActions = map[string]bool{
	"RESTART_POD":            true,
	"SCALE_DEPLOYMENT":       true,
	"CILIUM_QUARANTINE_EBPF": true,
	"UNQUARANTINE_POD":       true,
	"ESCALATE":               true,
}

// validateRequest decides whether a request may touch the cluster. It never contacts the cluster.
// allowed is an optional allowlist of namespaces; nil/empty means "any non-protected namespace".
func validateRequest(req ActionRequest, allowed map[string]bool) error {
	if !supportedActions[req.FinalAction] {
		return fmt.Errorf("%w: %q", ErrUnsupportedAction, req.FinalAction)
	}
	if !req.Approved {
		return ErrNotApproved
	}
	if strings.TrimSpace(req.TargetPod) == "" {
		return ErrInvalidTarget
	}
	if req.FinalAction == "ESCALATE" {
		return nil // never touches the cluster
	}
	if strings.TrimSpace(req.Namespace) == "" {
		return ErrNamespaceRequired
	}
	if protectedNamespaces[req.Namespace] {
		return fmt.Errorf("%w: %q", ErrProtectedNamespace, req.Namespace)
	}
	if len(allowed) > 0 && !allowed[req.Namespace] {
		return fmt.Errorf("%w: %q", ErrNamespaceNotAllowed, req.Namespace)
	}
	if req.FinalAction == "SCALE_DEPLOYMENT" && req.Replicas != nil && *req.Replicas < 1 {
		// Scaling to zero (or below) is an outage, not a remediation; the cap only bounds the top end.
		return fmt.Errorf("%w: got %d", ErrInvalidReplicas, *req.Replicas)
	}
	return nil
}
