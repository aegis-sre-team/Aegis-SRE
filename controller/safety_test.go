package main

import (
	"errors"
	"testing"
)

func baseReq(action string) ActionRequest {
	return ActionRequest{Approved: true, FinalAction: action, TargetPod: "cartservice-6f7d8c9b5-x2k4p", Namespace: testNS}
}

func TestValidateRejectsUnapproved(t *testing.T) {
	req := baseReq("RESTART_POD")
	req.Approved = false
	if err := validateRequest(req, nil); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("want ErrNotApproved, got %v", err)
	}
}

func TestValidateRejectsProtectedNamespaces(t *testing.T) {
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease", "aegis-system", "monitoring", "cilium-secrets"} {
		for _, action := range []string{"RESTART_POD", "SCALE_DEPLOYMENT", "CILIUM_QUARANTINE_EBPF", "UNQUARANTINE_POD"} {
			req := baseReq(action)
			req.Namespace = ns
			if err := validateRequest(req, nil); !errors.Is(err, ErrProtectedNamespace) {
				t.Errorf("%s/%s: want ErrProtectedNamespace, got %v", ns, action, err)
			}
		}
	}
}

func TestValidateRejectsEmptyNamespace(t *testing.T) {
	req := baseReq("RESTART_POD")
	req.Namespace = ""
	if err := validateRequest(req, nil); !errors.Is(err, ErrNamespaceRequired) {
		t.Fatalf("want ErrNamespaceRequired, got %v", err)
	}
}

func TestValidateRejectsUnsupportedAndCatastrophicActions(t *testing.T) {
	for _, a := range []string{"DELETE_NAMESPACE", "DELETE_NODE", "", "restart_pod "} {
		if err := validateRequest(baseReq(a), nil); !errors.Is(err, ErrUnsupportedAction) {
			t.Errorf("action %q: want ErrUnsupportedAction, got %v", a, err)
		}
	}
}

func TestValidateRejectsEmptyTarget(t *testing.T) {
	req := baseReq("RESTART_POD")
	req.TargetPod = ""
	if err := validateRequest(req, nil); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("want ErrInvalidTarget, got %v", err)
	}
}

func TestValidateAllowlistRestrictsNamespaces(t *testing.T) {
	allowed := map[string]bool{"online-boutique": true}
	if err := validateRequest(baseReq("RESTART_POD"), allowed); err != nil {
		t.Fatalf("allowed namespace rejected: %v", err)
	}
	req := baseReq("RESTART_POD")
	req.Namespace = "default"
	if err := validateRequest(req, allowed); !errors.Is(err, ErrNamespaceNotAllowed) {
		t.Fatalf("want ErrNamespaceNotAllowed, got %v", err)
	}
}

func TestValidateEscalateNeedsNoNamespace(t *testing.T) {
	req := ActionRequest{Approved: true, FinalAction: "ESCALATE", TargetPod: "p"}
	if err := validateRequest(req, nil); err != nil {
		t.Fatalf("ESCALATE must not require a namespace: %v", err)
	}
}

func TestValidateRejectsNonPositiveReplicas(t *testing.T) {
	for _, n := range []int32{0, -1, -100} {
		req := baseReq("SCALE_DEPLOYMENT")
		req.Replicas = int32Ptr(n)
		if err := validateRequest(req, nil); !errors.Is(err, ErrInvalidReplicas) {
			t.Errorf("replicas=%d: want ErrInvalidReplicas, got %v", n, err)
		}
	}
	ok := baseReq("SCALE_DEPLOYMENT")
	ok.Replicas = int32Ptr(1)
	if err := validateRequest(ok, nil); err != nil {
		t.Fatalf("replicas=1 must be accepted: %v", err)
	}
	if err := validateRequest(baseReq("SCALE_DEPLOYMENT"), nil); err != nil {
		t.Fatalf("omitted replicas must be accepted: %v", err)
	}
}
