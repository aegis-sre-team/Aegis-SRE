package main

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRestartPatchesOwningDeployment(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	res, err := r.Reconcile(context.Background(), baseReq("RESTART_POD"))
	if err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	if res.Status != "success" || res.Mode != "k8s_cluster" {
		t.Fatalf("unexpected result %+v", res)
	}
	dep, _ := cs.AppsV1().Deployments(testNS).Get(context.Background(), "cartservice", metav1.GetOptions{})
	if dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] == "" {
		t.Fatalf("deployment was not annotated for rollout restart: %+v", dep.Spec.Template.Annotations)
	}
	if _, err := cs.CoreV1().Pods(testNS).Get(context.Background(), "cartservice-6f7d8c9b5-x2k4p", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod must be left for the rollout to replace, not deleted: %v", err)
	}
}

func TestRestartBarePodIsRefused(t *testing.T) {
	r, cs := newTestReconciler(t, barePod("lonely", testNS))
	req := baseReq("RESTART_POD")
	req.TargetPod = "lonely"
	if _, err := r.Reconcile(context.Background(), req); !errors.Is(err, ErrNoWorkload) {
		t.Fatalf("a pod nothing would recreate must never be deleted; want ErrNoWorkload, got %v", err)
	}
	if _, err := cs.CoreV1().Pods(testNS).Get(context.Background(), "lonely", metav1.GetOptions{}); err != nil {
		t.Fatalf("bare pod must be left alone: %v", err)
	}
}

func TestRestartStatefulSetPodDeletesIt(t *testing.T) {
	r, cs := newTestReconciler(t, ownedPod("redis-0", testNS, "StatefulSet"))
	req := baseReq("RESTART_POD")
	req.TargetPod = "redis-0"
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	if _, err := cs.CoreV1().Pods(testNS).Get(context.Background(), "redis-0", metav1.GetOptions{}); err == nil {
		t.Fatal("a StatefulSet pod is recreated by its controller, so it should have been deleted")
	}
}

func TestRestartJobOwnedPodIsRefused(t *testing.T) {
	r, cs := newTestReconciler(t, ownedPod("batch-1-abcde", testNS, "Job"))
	req := baseReq("RESTART_POD")
	req.TargetPod = "batch-1-abcde"
	if _, err := r.Reconcile(context.Background(), req); !errors.Is(err, ErrNoWorkload) {
		t.Fatalf("want ErrNoWorkload for a Job pod, got %v", err)
	}
	if _, err := cs.CoreV1().Pods(testNS).Get(context.Background(), "batch-1-abcde", metav1.GetOptions{}); err != nil {
		t.Fatalf("Job pod must be left alone: %v", err)
	}
}

func TestRestartMissingPodReturnsNotFound(t *testing.T) {
	r, _ := newTestReconciler(t)
	_, err := r.Reconcile(context.Background(), baseReq("RESTART_POD"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestScaleDefaultsToCurrentPlusOne(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	if _, err := r.Reconcile(context.Background(), baseReq("SCALE_DEPLOYMENT")); err != nil {
		t.Fatalf("scale failed: %v", err)
	}
	dep, _ := cs.AppsV1().Deployments(testNS).Get(context.Background(), "cartservice", metav1.GetOptions{})
	if *dep.Spec.Replicas != 2 {
		t.Fatalf("want 2 replicas, got %d", *dep.Spec.Replicas)
	}
}

func TestScaleIsCappedAtMaxReplicas(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(4)...)
	r.MaxReplicas = 4
	res, err := r.Reconcile(context.Background(), baseReq("SCALE_DEPLOYMENT"))
	if err != nil {
		t.Fatalf("scale failed: %v", err)
	}
	dep, _ := cs.AppsV1().Deployments(testNS).Get(context.Background(), "cartservice", metav1.GetOptions{})
	if *dep.Spec.Replicas != 4 {
		t.Fatalf("cap breached: %d", *dep.Spec.Replicas)
	}
	if res.Status != "success" {
		t.Fatalf("at-cap scale should be a harmless success, got %+v", res)
	}
}

func TestScaleHonoursExplicitReplicasButStillCaps(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	r.MaxReplicas = 3
	req := baseReq("SCALE_DEPLOYMENT")
	req.Replicas = int32Ptr(10)
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("scale failed: %v", err)
	}
	dep, _ := cs.AppsV1().Deployments(testNS).Get(context.Background(), "cartservice", metav1.GetOptions{})
	if *dep.Spec.Replicas != 3 {
		t.Fatalf("want cap 3, got %d", *dep.Spec.Replicas)
	}
}

func TestScaleBarePodHasNoWorkload(t *testing.T) {
	r, _ := newTestReconciler(t, barePod("lonely", testNS))
	req := baseReq("SCALE_DEPLOYMENT")
	req.TargetPod = "lonely"
	if _, err := r.Reconcile(context.Background(), req); !errors.Is(err, ErrNoWorkload) {
		t.Fatalf("want ErrNoWorkload, got %v", err)
	}
}

func TestDryRunMutatesNothing(t *testing.T) {
	for _, action := range []string{"RESTART_POD", "SCALE_DEPLOYMENT", "CILIUM_QUARANTINE_EBPF", "UNQUARANTINE_POD"} {
		r, cs := newTestReconciler(t, boutiqueObjects(1)...)
		r.DryRun = true
		res, err := r.Reconcile(context.Background(), baseReq(action))
		if err != nil {
			t.Fatalf("%s dry-run failed: %v", action, err)
		}
		if res.Mode != "dry_run" || res.Status != "success" {
			t.Fatalf("%s: unexpected dry-run result %+v", action, res)
		}
		if verbs := mutatingVerbs(cs.Actions()); len(verbs) != 0 {
			t.Fatalf("%s: dry-run mutated the cluster: %v", action, verbs)
		}
	}
}

func TestReconcileEnforcesSafetyBeforeAnyClusterCall(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	req := baseReq("RESTART_POD")
	req.Namespace = "kube-system"
	if _, err := r.Reconcile(context.Background(), req); !errors.Is(err, ErrProtectedNamespace) {
		t.Fatalf("want ErrProtectedNamespace, got %v", err)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("rejected request touched the cluster (%d actions)", n)
	}
}

func TestEscalateTouchesNothing(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	res, err := r.Reconcile(context.Background(), ActionRequest{Approved: true, FinalAction: "ESCALATE", TargetPod: "p", Namespace: testNS})
	if err != nil || res.Status != "success" {
		t.Fatalf("escalate: %+v %v", res, err)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("escalate touched the cluster (%d actions)", n)
	}
}
