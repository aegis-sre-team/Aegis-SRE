package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
)

const testPod = "cartservice-6f7d8c9b5-x2k4p"

func TestLabelValueShortNameUnchanged(t *testing.T) {
	if got := QuarantineLabelValue(testPod); got != testPod {
		t.Fatalf("got %q", got)
	}
}

func TestLabelValueLongNameMatchesPythonVector(t *testing.T) {
	name := "pod-" + strings.Repeat("0123456789", 8) // 84 chars; same vector as test_controller.py
	want := "pod-012345678901234567890123456789012345678901234567-e7d54e8fa2"
	got := QuarantineLabelValue(name)
	if got != want {
		t.Fatalf("label drift between Go and Python:\n got %q\nwant %q", got, want)
	}
	if len(got) != 63 {
		t.Fatalf("length %d", len(got))
	}
}

func TestLabelValueBoundary(t *testing.T) {
	if got := QuarantineLabelValue(strings.Repeat("a", 63)); got != strings.Repeat("a", 63) {
		t.Fatalf("63 chars must be unchanged")
	}
	if got := QuarantineLabelValue(strings.Repeat("a", 64)); len(got) != 63 || got == strings.Repeat("a", 63) {
		t.Fatalf("64 chars must be hashed to 63, got %q", got)
	}
}

func TestQuarantineCreatesDenyPolicyAndLabelsPod(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	res, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil {
		t.Fatalf("quarantine failed: %v", err)
	}
	wantName := "aegis-quarantine-" + testPod
	if res.Status != "success" || res.PolicyName != wantName {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.Forensics == nil {
		t.Fatal("quarantine must return forensics")
	}

	pod, _ := cs.CoreV1().Pods(testNS).Get(context.Background(), testPod, metav1.GetOptions{})
	if pod.Labels[quarantineLabel] != QuarantineLabelValue(testPod) {
		t.Fatalf("pod not labelled: %v", pod.Labels)
	}
	if pod.Labels["app"] != "cartservice" {
		t.Fatalf("existing labels must be preserved: %v", pod.Labels)
	}

	pol, err := r.DynamicClient.Resource(ciliumGVR).Namespace(testNS).Get(context.Background(), wantName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("policy missing: %v", err)
	}
	spec := pol.Object["spec"].(map[string]interface{})
	sel := spec["endpointSelector"].(map[string]interface{})["matchLabels"].(map[string]interface{})
	if sel[quarantineLabel] != QuarantineLabelValue(testPod) {
		t.Fatalf("selector wrong: %v", sel)
	}
	ing := spec["ingressDeny"].([]interface{})[0].(map[string]interface{})["fromEntities"].([]interface{})
	egr := spec["egressDeny"].([]interface{})[0].(map[string]interface{})["toEntities"].([]interface{})
	if ing[0] != "all" || egr[0] != "all" {
		t.Fatalf("deny rules wrong: %v %v", ing, egr)
	}
	if _, has := spec["ingress"]; has {
		t.Fatal("must not use empty allow lists")
	}
}

func TestQuarantineTwiceIsIdempotent(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF")); err != nil {
			t.Fatalf("call %d failed: %v", i+1, err)
		}
	}
	list, err := r.DynamicClient.Resource(ciliumGVR).Namespace(testNS).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("want exactly one policy, got %d (%v)", len(list.Items), err)
	}
}

func TestQuarantineCapturesForensicsBeforeIsolating(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	if _, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF")); err != nil {
		t.Fatal(err)
	}
	firstRead, firstWrite := -1, -1
	for i, a := range cs.Actions() {
		isEvents := a.GetVerb() == "list" && a.GetResource().Resource == "events"
		isLogs := a.GetVerb() == "get" && a.GetResource().Resource == "pods" && a.GetSubresource() == "log"
		isPatch := a.GetVerb() == "patch" && a.GetResource().Resource == "pods"
		if (isEvents || isLogs) && firstRead == -1 {
			firstRead = i
		}
		if isPatch && firstWrite == -1 {
			firstWrite = i
		}
	}
	if firstRead == -1 || firstWrite == -1 || firstRead > firstWrite {
		t.Fatalf("forensics must be read before the pod is relabelled (read=%d write=%d)", firstRead, firstWrite)
	}
}

func TestForensicsContentIsRealAndFilteredToThePod(t *testing.T) {
	objs := boutiqueObjects(1)
	objs = append(objs,
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: testNS}, InvolvedObject: corev1.ObjectReference{Name: testPod}, Type: "Warning", Reason: "Unhealthy", Message: "probe failed"},
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "e2", Namespace: testNS}, InvolvedObject: corev1.ObjectReference{Name: "someone-else"}, Type: "Normal", Reason: "Started", Message: "other pod"},
	)
	r, _ := newTestReconciler(t, objs...)
	res, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil {
		t.Fatal(err)
	}
	f := res.Forensics
	if f.Pod != testPod || f.Namespace != testNS || f.NodeName != "node-1" || f.PodIP != "10.42.0.9" || f.Phase != "Running" {
		t.Fatalf("pod facts wrong: %+v", f)
	}
	if len(f.Events) != 1 || !strings.Contains(f.Events[0], "probe failed") {
		t.Fatalf("events must be filtered to this pod: %v", f.Events)
	}
	if _, ok := f.Logs["server"]; !ok {
		t.Fatalf("expected logs for container 'server': %v", f.Logs)
	}
	if f.CapturedAt == "" {
		t.Fatal("missing capture time")
	}
}

func TestForensicsProcessListNilWithoutExec(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	res, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Forensics.ProcessList != nil {
		t.Fatal("no exec configured: process list must be absent, not invented")
	}
	if !containsSub(res.Forensics.Errors, "exec") {
		t.Fatalf("absence must be explained: %v", res.Forensics.Errors)
	}
}

func TestForensicsProcessListUsesExec(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	r.Exec = func(ctx context.Context, ns, pod, container string, cmd []string) (string, error) {
		return "PID USER COMMAND\n1 root /app\n77 root /bin/sh -i", nil
	}
	res, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Forensics.ProcessList == nil || !strings.Contains(*res.Forensics.ProcessList, "/bin/sh -i") {
		t.Fatalf("process list missing: %+v", res.Forensics.ProcessList)
	}
}

func TestQuarantineProceedsWhenForensicsFail(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	cs.PrependReactor("list", "events", func(a clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("events API down")
	})
	r.Exec = func(ctx context.Context, ns, pod, container string, cmd []string) (string, error) {
		return "", errors.New("exec forbidden")
	}
	res, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil {
		t.Fatalf("forensics failure must never block isolation: %v", err)
	}
	if res.Status != "success" || res.PolicyName == "" {
		t.Fatalf("isolation did not complete: %+v", res)
	}
	if !containsSub(res.Forensics.Errors, "events") || !containsSub(res.Forensics.Errors, "exec forbidden") {
		t.Fatalf("failures must be recorded: %v", res.Forensics.Errors)
	}
}

func TestQuarantineMissingPodNotFound(t *testing.T) {
	r, _ := newTestReconciler(t)
	_, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	list, _ := r.DynamicClient.Resource(ciliumGVR).Namespace(testNS).List(context.Background(), metav1.ListOptions{})
	if len(list.Items) != 0 {
		t.Fatal("no policy may be created for a missing pod")
	}
}

func TestUnquarantineRemovesPolicyAndLabel(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(1)...)
	if _, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF")); err != nil {
		t.Fatal(err)
	}
	res, err := r.Reconcile(context.Background(), baseReq("UNQUARANTINE_POD"))
	if err != nil || res.Status != "success" {
		t.Fatalf("unquarantine failed: %+v %v", res, err)
	}
	_, err = r.DynamicClient.Resource(ciliumGVR).Namespace(testNS).Get(context.Background(), "aegis-quarantine-"+testPod, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("policy should be gone, got %v", err)
	}
	pod, _ := cs.CoreV1().Pods(testNS).Get(context.Background(), testPod, metav1.GetOptions{})
	if _, has := pod.Labels[quarantineLabel]; has {
		t.Fatalf("label should be removed: %v", pod.Labels)
	}
	if pod.Labels["app"] != "cartservice" {
		t.Fatalf("other labels must survive: %v", pod.Labels)
	}
}

func TestUnquarantineWithoutPolicyOrPodIsOK(t *testing.T) {
	r, _ := newTestReconciler(t)
	res, err := r.Reconcile(context.Background(), baseReq("UNQUARANTINE_POD"))
	if err != nil || res.Status != "success" {
		t.Fatalf("idempotent unquarantine failed: %+v %v", res, err)
	}
}

func containsSub(items []string, sub string) bool {
	for _, it := range items {
		if strings.Contains(it, sub) {
			return true
		}
	}
	return false
}

func TestSecondQuarantineIsANoOpThatKeepsTheFirstEvidence(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	first, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil || first.Forensics == nil {
		t.Fatalf("first quarantine failed: %+v %v", first, err)
	}
	second, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil {
		t.Fatalf("second quarantine failed: %v", err)
	}
	if second.Status != "success" || second.PolicyName != first.PolicyName {
		t.Fatalf("second call should succeed against the same policy: %+v", second)
	}
	if second.Forensics != nil {
		t.Fatal("an already-isolated pod must not be re-snapshotted (the first snapshot is the pre-isolation evidence)")
	}
	if !strings.Contains(second.Message, "already quarantined") {
		t.Fatalf("message should say so: %q", second.Message)
	}
}

func TestQuarantineRepairsAMissingPolicy(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	if _, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF")); err != nil {
		t.Fatal(err)
	}
	// someone deleted the policy but the label is still there: not "already quarantined" any more
	_ = r.DynamicClient.Resource(ciliumGVR).Namespace(testNS).Delete(context.Background(), "aegis-quarantine-"+testPod, metav1.DeleteOptions{})
	res, err := r.Reconcile(context.Background(), baseReq("CILIUM_QUARANTINE_EBPF"))
	if err != nil || res.Forensics == nil {
		t.Fatalf("a missing policy must be re-created with fresh forensics: %+v %v", res, err)
	}
	if _, err := r.DynamicClient.Resource(ciliumGVR).Namespace(testNS).Get(context.Background(), "aegis-quarantine-"+testPod, metav1.GetOptions{}); err != nil {
		t.Fatalf("policy was not re-created: %v", err)
	}
}
