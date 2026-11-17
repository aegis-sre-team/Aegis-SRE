package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func postReconcile(h http.Handler, token string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	switch b := body.(type) {
	case string:
		buf.WriteString(b)
	default:
		_ = json.NewEncoder(&buf).Encode(b)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reconcile", &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServerRequiresBearerToken(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	r.DryRun = true
	h := newServer(r, "tok")

	if rec := postReconcile(h, "", baseReq("RESTART_POD")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401 got %d", rec.Code)
	}
	if rec := postReconcile(h, "wrong", baseReq("RESTART_POD")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401 got %d", rec.Code)
	}
	if rec := postReconcile(h, "tok", baseReq("RESTART_POD")); rec.Code != http.StatusOK {
		t.Fatalf("right token: want 200 got %d (%s)", rec.Code, rec.Body.String())
	}
	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("/healthz must stay open for probes, got %d", health.Code)
	}
}

func TestServerWithoutTokenConfiguredIsOpen(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	r.DryRun = true
	if rec := postReconcile(newServer(r, ""), "", baseReq("RESTART_POD")); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestServerStatusCodes(t *testing.T) {
	unapproved := baseReq("RESTART_POD")
	unapproved.Approved = false
	protected := baseReq("RESTART_POD")
	protected.Namespace = "kube-system"
	noNS := baseReq("RESTART_POD")
	noNS.Namespace = ""
	missing := baseReq("RESTART_POD")
	missing.TargetPod = "ghost-pod"

	cases := []struct {
		name       string
		body       interface{}
		wantCode   int
		wantStatus string
	}{
		{"success", baseReq("RESTART_POD"), 200, "success"},
		{"unapproved is skipped", unapproved, 200, "skipped"},
		{"protected namespace", protected, 403, "error"},
		{"missing namespace", noNS, 400, "error"},
		{"unsupported action", baseReq("DELETE_NAMESPACE"), 400, "error"},
		{"pod not found", missing, 404, "error"},
		{"bad json", "{not json", 400, "error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, boutiqueObjects(1)...)
			rec := postReconcile(newServer(r, ""), "", c.body)
			if rec.Code != c.wantCode {
				t.Fatalf("code: want %d got %d (%s)", c.wantCode, rec.Code, rec.Body.String())
			}
			var out map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if out["status"] != c.wantStatus {
				t.Fatalf("status field: want %q got %v", c.wantStatus, out["status"])
			}
		})
	}
}

func TestServerRejectsGetOnReconcile(t *testing.T) {
	r, _ := newTestReconciler(t)
	rec := httptest.NewRecorder()
	newServer(r, "").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reconcile", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func getJSON(t *testing.T, h http.Handler, token, url string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestStatusReportsDeploymentRollout(t *testing.T) {
	objs := boutiqueObjects(2)
	dep := objs[0].(*appsv1.Deployment)
	dep.Status = appsv1.DeploymentStatus{Replicas: 2, ReadyReplicas: 2, UpdatedReplicas: 2}
	r, _ := newTestReconciler(t, objs...)
	code, out := getJSON(t, newServer(r, "tok"), "tok", "/api/v1/status?namespace="+testNS+"&pod="+testPod)
	if code != 200 || out["found"] != true || out["phase"] != "Running" {
		t.Fatalf("status wrong: %d %v", code, out)
	}
	d := out["deployment"].(map[string]interface{})
	if d["name"] != "cartservice" || d["desired"].(float64) != 2 || d["ready"].(float64) != 2 || d["updated"].(float64) != 2 {
		t.Fatalf("deployment status wrong: %v", d)
	}
	if out["quarantined"] != false {
		t.Fatalf("quarantined should be false: %v", out["quarantined"])
	}
}

func TestStatusForGonePodUsesDeploymentHint(t *testing.T) {
	objs := boutiqueObjects(1)
	dep := objs[0].(*appsv1.Deployment)
	dep.Status = appsv1.DeploymentStatus{Replicas: 1, ReadyReplicas: 1, UpdatedReplicas: 1}
	r, _ := newTestReconciler(t, objs...)
	code, out := getJSON(t, newServer(r, ""), "", "/api/v1/status?namespace="+testNS+"&pod=old-pod-gone&deployment=cartservice")
	if code != 200 || out["found"] != false {
		t.Fatalf("gone pod must be reported as not found: %d %v", code, out)
	}
	d := out["deployment"].(map[string]interface{})
	if d["name"] != "cartservice" || d["ready"].(float64) != 1 {
		t.Fatalf("deployment hint ignored: %v", d)
	}
}

func TestStatusReportsQuarantine(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	if _, err := r.Reconcile(contextBackground(), baseReq("CILIUM_QUARANTINE_EBPF")); err != nil {
		t.Fatal(err)
	}
	_, out := getJSON(t, newServer(r, ""), "", "/api/v1/status?namespace="+testNS+"&pod="+testPod)
	if out["quarantined"] != true {
		t.Fatalf("quarantine not reported: %v", out)
	}
}

func TestStatusRequiresNamespaceAndPod(t *testing.T) {
	r, _ := newTestReconciler(t)
	if code, _ := getJSON(t, newServer(r, ""), "", "/api/v1/status?pod=x"); code != 400 {
		t.Fatalf("missing namespace: got %d", code)
	}
	if code, _ := getJSON(t, newServer(r, ""), "", "/api/v1/status?namespace=a"); code != 400 {
		t.Fatalf("missing pod: got %d", code)
	}
}

func TestListPodsReturnsLiveSummaries(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	code, out := getJSON(t, newServer(r, ""), "", "/api/v1/pods?namespace="+testNS)
	if code != 200 {
		t.Fatalf("got %d", code)
	}
	pods := out["pods"].([]interface{})
	if len(pods) != 1 {
		t.Fatalf("want 1 pod, got %v", pods)
	}
	p := pods[0].(map[string]interface{})
	if p["name"] != testPod || p["phase"] != "Running" || p["node"] != "node-1" {
		t.Fatalf("pod summary wrong: %v", p)
	}
	if code, _ := getJSON(t, newServer(r, ""), "", "/api/v1/pods"); code != 400 {
		t.Fatalf("namespace is required: got %d", code)
	}
}

func TestRestartResultNamesTheWorkload(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	res, err := r.Reconcile(contextBackground(), baseReq("RESTART_POD"))
	if err != nil || res.Workload != "cartservice" {
		t.Fatalf("restart must report the Deployment so the brain can verify the rollout: %+v %v", res, err)
	}
}

func TestStatusReportsRolloutGenerationAndTotals(t *testing.T) {
	objs := boutiqueObjects(2)
	dep := objs[0].(*appsv1.Deployment)
	dep.Generation = 3
	dep.Status = appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 2, ReadyReplicas: 2, UpdatedReplicas: 2}
	r, _ := newTestReconciler(t, objs...)
	_, out := getJSON(t, newServer(r, ""), "", "/api/v1/status?namespace="+testNS+"&pod="+testPod)
	d := out["deployment"].(map[string]interface{})
	if d["generation"].(float64) != 3 || d["observed_generation"].(float64) != 3 || d["replicas"].(float64) != 2 {
		t.Fatalf("rollout fields missing: %v", d)
	}
}

func TestServerRejectsNonPositiveReplicasBeforeTouchingTheCluster(t *testing.T) {
	r, cs := newTestReconciler(t, boutiqueObjects(2)...)
	req := baseReq("SCALE_DEPLOYMENT")
	req.Replicas = int32Ptr(0)
	rec := postReconcile(newServer(r, ""), "", req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("a rejected request touched the cluster (%d actions)", n)
	}
}

func TestStatusReportsATerminatingPod(t *testing.T) {
	objs := boutiqueObjects(1)
	pod := objs[2].(*corev1.Pod)
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	r, _ := newTestReconciler(t, objs...)
	_, out := getJSON(t, newServer(r, ""), "", "/api/v1/status?namespace="+testNS+"&pod="+testPod)
	if out["terminating"] != true {
		t.Fatalf("a pod with a deletionTimestamp must be reported as terminating: %v", out)
	}
	healthy := boutiqueObjects(1)
	r2, _ := newTestReconciler(t, healthy...)
	_, out2 := getJSON(t, newServer(r2, ""), "", "/api/v1/status?namespace="+testNS+"&pod="+testPod)
	if out2["terminating"] != false {
		t.Fatalf("a normal pod must not be terminating: %v", out2)
	}
}

func TestServerRequiresTheBearerSchemeNotJustTheToken(t *testing.T) {
	r, _ := newTestReconciler(t, boutiqueObjects(1)...)
	r.DryRun = true
	h := newServer(r, "tok")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reconcile", bytes.NewBufferString(`{"approved":true,"final_action":"ESCALATE","target_pod":"p"}`))
	req.Header.Set("Authorization", "tok") // bare token, no scheme
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a bare token must not authenticate, got %d", rec.Code)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/reconcile", bytes.NewBufferString(`{"approved":true,"final_action":"ESCALATE","target_pod":"p"}`))
	req2.Header.Set("Authorization", "Bearer tok")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("a proper Bearer token must work, got %d", rec2.Code)
	}
}
