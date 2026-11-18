package main

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

var chaosT0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func chaosDeployment(name string, replicas, ready int32, annotations map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: chaosNamespace, Annotations: annotations},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(replicas)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: ready},
	}
}

// allChaosDeployments is one stopped Deployment per scenario, as the manifests ship them.
func allChaosDeployments() []runtime.Object {
	var objs []runtime.Object
	for _, dep := range chaosScenarios {
		objs = append(objs, chaosDeployment(dep, 0, 0, nil))
	}
	return objs
}

func newChaosReconciler(t *testing.T, enabled bool, objs ...runtime.Object) (*ActionReconciler, *fake.Clientset) {
	t.Helper()
	r, cs := newTestReconciler(t, objs...)
	r.ChaosEnabled = enabled
	r.Now = func() time.Time { return chaosT0 }
	return r, cs
}

func replicasOf(t *testing.T, cs *fake.Clientset, name string) int32 {
	t.Helper()
	d, err := cs.AppsV1().Deployments(chaosNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	return *d.Spec.Replicas
}

func annotationOf(t *testing.T, cs *fake.Clientset, name string) (string, bool) {
	t.Helper()
	d, err := cs.AppsV1().Deployments(chaosNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	v, ok := d.Annotations[chaosExpiresAnnotation]
	return v, ok
}

func TestSetChaosOnScalesToOneAndSetsExpiry(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)

	got, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "cpu-spike", State: "on"})
	if err != nil {
		t.Fatalf("SetChaos: %v", err)
	}
	if replicasOf(t, cs, "chaos-cpu-spike") != 1 {
		t.Fatalf("want 1 replica")
	}
	want := chaosT0.Add(30 * time.Minute).Format(time.RFC3339)
	if v, _ := annotationOf(t, cs, "chaos-cpu-spike"); v != want {
		t.Fatalf("expiry annotation = %q, want %q", v, want)
	}
	if got.ID != "cpu-spike" || got.Deployment != "chaos-cpu-spike" || got.Replicas != 1 || got.ExpiresAt != want || !got.Installed {
		t.Fatalf("unexpected result %+v", got)
	}
}

func TestSetChaosOffScalesToZeroAndClearsAnnotation(t *testing.T) {
	running := chaosDeployment("chaos-oom", 1, 1, map[string]string{chaosExpiresAnnotation: chaosT0.Add(time.Hour).Format(time.RFC3339)})
	r, cs := newChaosReconciler(t, true, running)

	got, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "oom", State: "off"})
	if err != nil {
		t.Fatalf("SetChaos: %v", err)
	}
	if replicasOf(t, cs, "chaos-oom") != 0 {
		t.Fatalf("want 0 replicas")
	}
	if _, ok := annotationOf(t, cs, "chaos-oom"); ok {
		t.Fatalf("expiry annotation must be removed")
	}
	if got.Replicas != 0 || got.ExpiresAt != "" {
		t.Fatalf("unexpected result %+v", got)
	}
}

func TestSetChaosRejectsUnknownScenarioWithoutClusterCalls(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	for _, id := range []string{"", "../x", "CPU-SPIKE", "chaos-cpu-spike"} {
		if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: id, State: "on"}); !errors.Is(err, ErrUnknownScenario) {
			t.Fatalf("scenario %q: want ErrUnknownScenario, got %v", id, err)
		}
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("an unknown scenario must not reach the cluster, saw %d calls", n)
	}
}

func TestSetChaosDisabledMakesNoClusterCalls(t *testing.T) {
	r, cs := newChaosReconciler(t, false, allChaosDeployments()...)
	if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "cpu-spike", State: "on"}); !errors.Is(err, ErrChaosDisabled) {
		t.Fatalf("SetChaos: want ErrChaosDisabled, got %v", err)
	}
	if _, err := r.ListChaos(context.Background()); !errors.Is(err, ErrChaosDisabled) {
		t.Fatalf("ListChaos: want ErrChaosDisabled, got %v", err)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("a disabled switch must not reach the cluster, saw %d calls", n)
	}
}

func TestSetChaosTTLRules(t *testing.T) {
	cases := []struct {
		ttl     int
		minutes int
	}{{0, 30}, {45, 45}, {100000, 120}}
	for _, c := range cases {
		r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
		if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "cpu-spike", State: "on", TTLMinutes: c.ttl}); err != nil {
			t.Fatalf("ttl %d: %v", c.ttl, err)
		}
		want := chaosT0.Add(time.Duration(c.minutes) * time.Minute).Format(time.RFC3339)
		if v, _ := annotationOf(t, cs, "chaos-cpu-spike"); v != want {
			t.Fatalf("ttl %d: expiry %q, want %q", c.ttl, v, want)
		}
	}
	r, _ := newChaosReconciler(t, true, allChaosDeployments()...)
	if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "cpu-spike", State: "on", TTLMinutes: -1}); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("ttl -1: want ErrInvalidTTL, got %v", err)
	}
}

func TestSetChaosInvalidState(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "cpu-spike", State: "maybe"}); !errors.Is(err, ErrInvalidChaosState) {
		t.Fatalf("want ErrInvalidChaosState, got %v", err)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("an invalid state must not reach the cluster, saw %d calls", n)
	}
}

func TestSetChaosIsIdempotent(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	ctx := context.Background()

	if _, err := r.SetChaos(ctx, ChaosRequest{Scenario: "crashloop", State: "on"}); err != nil {
		t.Fatal(err)
	}
	first, _ := annotationOf(t, cs, "chaos-crashloop")
	r.Now = func() time.Time { return chaosT0.Add(10 * time.Minute) }
	if _, err := r.SetChaos(ctx, ChaosRequest{Scenario: "crashloop", State: "on"}); err != nil {
		t.Fatal(err)
	}
	second, _ := annotationOf(t, cs, "chaos-crashloop")
	if replicasOf(t, cs, "chaos-crashloop") != 1 {
		t.Fatalf("starting twice must leave 1 replica")
	}
	if second <= first {
		t.Fatalf("starting again must move the expiry later: %q then %q", first, second)
	}

	for i := 0; i < 2; i++ {
		if _, err := r.SetChaos(ctx, ChaosRequest{Scenario: "crashloop", State: "off"}); err != nil {
			t.Fatalf("stop #%d: %v", i+1, err)
		}
	}
	if replicasOf(t, cs, "chaos-crashloop") != 0 {
		t.Fatalf("want 0 replicas after stopping")
	}
}

func TestSetChaosMissingDeploymentIsNotFound(t *testing.T) {
	r, _ := newChaosReconciler(t, true)
	if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "oom", State: "on"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestListChaosMarksUninstalledScenarios(t *testing.T) {
	r, _ := newChaosReconciler(t, true,
		chaosDeployment("chaos-oom", 0, 0, nil),
		chaosDeployment("chaos-cpu-spike", 1, 1, map[string]string{chaosExpiresAnnotation: chaosT0.Add(5 * time.Minute).Format(time.RFC3339)}),
		chaosDeployment("chaos-http-500", 0, 0, nil),
	)
	list, err := r.ListChaos(context.Background())
	if err != nil {
		t.Fatalf("ListChaos: %v", err)
	}
	if len(list) != len(chaosScenarios) {
		t.Fatalf("want %d scenarios, got %d", len(chaosScenarios), len(list))
	}
	installed := 0
	for i, s := range list {
		if i > 0 && list[i-1].ID >= s.ID {
			t.Fatalf("list must be sorted by id: %q before %q", list[i-1].ID, s.ID)
		}
		if s.Installed {
			installed++
		}
		if s.ID == "cpu-spike" && (!s.Installed || s.Replicas != 1 || s.Ready != 1 || s.ExpiresAt == "") {
			t.Fatalf("running scenario reported wrongly: %+v", s)
		}
		if s.ID == "restart-storm" && s.Installed {
			t.Fatalf("a missing deployment must be reported as not installed: %+v", s)
		}
	}
	if installed != 3 {
		t.Fatalf("want 3 installed scenarios, got %d", installed)
	}
}

func TestStopExpiredChaos(t *testing.T) {
	past := chaosT0.Add(-time.Minute).Format(time.RFC3339)
	future := chaosT0.Add(time.Hour).Format(time.RFC3339)
	r, cs := newChaosReconciler(t, true,
		chaosDeployment("chaos-cpu-spike", 1, 1, map[string]string{chaosExpiresAnnotation: past}),
		chaosDeployment("chaos-oom", 1, 1, map[string]string{chaosExpiresAnnotation: future}),
		chaosDeployment("chaos-crashloop", 1, 0, map[string]string{chaosExpiresAnnotation: "not-a-time"}),
		chaosDeployment("chaos-http-500", 1, 1, nil),
		chaosDeployment("chaos-shell-injection", 0, 0, nil),
	)
	stopped, err := r.StopExpiredChaos(context.Background())
	if err != nil {
		t.Fatalf("StopExpiredChaos: %v", err)
	}
	if stopped != 3 {
		t.Fatalf("want 3 stopped (expired, garbage, no annotation), got %d", stopped)
	}
	for _, name := range []string{"chaos-cpu-spike", "chaos-crashloop", "chaos-http-500"} {
		if replicasOf(t, cs, name) != 0 {
			t.Fatalf("%s should have been stopped", name)
		}
	}
	if replicasOf(t, cs, "chaos-oom") != 1 {
		t.Fatalf("a scenario that has not expired must keep running")
	}
}

func TestSetChaosRetriesWhenTheDeploymentChangedUnderneath(t *testing.T) {
	// The Deployment controller rewrites status all the time, so a Get followed by an Update can lose the race.
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	conflicts := 1
	cs.PrependReactor("update", "deployments", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if conflicts > 0 {
			conflicts--
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "deployments"}, "chaos-cpu-spike", errors.New("the object has been modified"))
		}
		return false, nil, nil
	})
	if _, err := r.SetChaos(context.Background(), ChaosRequest{Scenario: "cpu-spike", State: "on"}); err != nil {
		t.Fatalf("a single write conflict must be retried, got %v", err)
	}
	if conflicts != 0 {
		t.Fatalf("the conflict was never injected, so the test proved nothing")
	}
	if replicasOf(t, cs, "chaos-cpu-spike") != 1 {
		t.Fatalf("the retry did not apply the change")
	}
}

func TestStopExpiredChaosDoesNothingWhenDisabled(t *testing.T) {
	r, cs := newChaosReconciler(t, false, chaosDeployment("chaos-cpu-spike", 1, 1, nil))
	if n, err := r.StopExpiredChaos(context.Background()); err != nil || n != 0 {
		t.Fatalf("want 0 stopped and no error when disabled, got %d, %v", n, err)
	}
	if replicasOf(t, cs, "chaos-cpu-spike") != 1 {
		t.Fatalf("a disabled switch must not touch the cluster")
	}
}
