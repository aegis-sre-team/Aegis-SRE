package main

import (
	"errors"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ciliumGVR addresses CiliumNetworkPolicy objects (cilium.io/v2).
var ciliumGVR = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}

// Sentinel errors. The HTTP layer maps them to status codes; callers use errors.Is.
var (
	ErrNotApproved         = errors.New("action not approved by guardrails")
	ErrProtectedNamespace  = errors.New("namespace is protected")
	ErrNamespaceRequired   = errors.New("namespace is required")
	ErrNamespaceNotAllowed = errors.New("namespace is not in the allowed namespaces")
	ErrUnsupportedAction   = errors.New("unsupported action")
	ErrInvalidTarget       = errors.New("target pod is required")
	ErrNotFound            = errors.New("not found")
	ErrNoWorkload          = errors.New("pod has no owning Deployment")
	ErrInvalidReplicas     = errors.New("replicas must be at least 1")

	// Chaos controls (see chaos.go).
	ErrChaosDisabled     = errors.New("chaos controls are disabled (set CHAOS_ENABLED=true on the controller)")
	ErrUnknownScenario   = errors.New("unknown chaos scenario")
	ErrInvalidChaosState = errors.New("chaos state must be \"on\" or \"off\"")
	ErrInvalidTTL        = errors.New("ttl_minutes must not be negative")
	ErrNoCluster         = errors.New("no cluster connection")
)

// ActionRequest is a guardrail-approved decision received from the Aegis brain.
type ActionRequest struct {
	Approved       bool   `json:"approved"`
	FinalAction    string `json:"final_action"`
	TargetPod      string `json:"target_pod"`
	Namespace      string `json:"namespace"`
	ProblemType    string `json:"problem_type"`
	MitreTechnique string `json:"mitre_technique,omitempty"`
	Reason         string `json:"reason"`
	Replicas       *int32 `json:"replicas,omitempty"`
}

// ActionResult is returned to the brain for every request that got past validation.
type ActionResult struct {
	Status     string     `json:"status"` // success | error | skipped
	Mode       string     `json:"mode"`   // k8s_cluster | dry_run | none
	Action     string     `json:"action"`
	Target     string     `json:"target"`
	Namespace  string     `json:"namespace"`
	Message    string     `json:"message"`
	PolicyName string     `json:"policy_name,omitempty"`
	Workload   string     `json:"workload,omitempty"` // owning Deployment, so the brain can verify the rollout
	Forensics  *Forensics `json:"forensics,omitempty"`
}
