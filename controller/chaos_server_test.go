package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func chaosCall(h http.Handler, method, token string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/api/v1/chaos", &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestChaosRoutesRequireToken(t *testing.T) {
	r, _ := newChaosReconciler(t, true, allChaosDeployments()...)
	h := newServer(r, "tok")
	if rec := chaosCall(h, http.MethodGet, "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without token: want 401, got %d", rec.Code)
	}
	if rec := chaosCall(h, http.MethodPost, "wrong", ChaosRequest{Scenario: "oom", State: "on"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST with wrong token: want 401, got %d", rec.Code)
	}
}

func TestChaosDisabledReturns403(t *testing.T) {
	r, cs := newChaosReconciler(t, false, allChaosDeployments()...)
	h := newServer(r, "tok")
	if rec := chaosCall(h, http.MethodGet, "tok", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("GET while disabled: want 403, got %d", rec.Code)
	}
	if rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "oom", State: "on"}); rec.Code != http.StatusForbidden {
		t.Fatalf("POST while disabled: want 403, got %d", rec.Code)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("a disabled switch must not reach the cluster, saw %d calls", n)
	}
}

func TestChaosStartStopRoundTrip(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	h := newServer(r, "tok")

	rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "network-recon", State: "on", TTLMinutes: 10})
	if rec.Code != http.StatusOK {
		t.Fatalf("start: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var started ChaosScenario
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil || started.Replicas != 1 || started.ID != "network-recon" {
		t.Fatalf("start body = %s (%v)", rec.Body.String(), err)
	}
	if replicasOf(t, cs, "chaos-network-recon") != 1 {
		t.Fatalf("deployment was not scaled up")
	}

	rec = chaosCall(h, http.MethodGet, "tok", nil)
	var list struct {
		Scenarios []ChaosScenario `json:"scenarios"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Scenarios) != len(chaosScenarios) {
		t.Fatalf("list: code %d body %s", rec.Code, rec.Body.String())
	}
	running := 0
	for _, s := range list.Scenarios {
		if s.Replicas == 1 {
			running++
		}
	}
	if running != 1 {
		t.Fatalf("want exactly one running scenario in the list, got %d", running)
	}

	rec = chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "network-recon", State: "off"})
	if rec.Code != http.StatusOK || replicasOf(t, cs, "chaos-network-recon") != 0 {
		t.Fatalf("stop: code %d, replicas %d", rec.Code, replicasOf(t, cs, "chaos-network-recon"))
	}
}

func TestChaosUnknownScenarioReturns400(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	h := newServer(r, "tok")
	for _, id := range []string{"", "../x", "kube-dns"} {
		if rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: id, State: "on"}); rec.Code != http.StatusBadRequest {
			t.Fatalf("scenario %q: want 400, got %d", id, rec.Code)
		}
	}
	if rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "oom", State: "maybe"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad state: want 400, got %d", rec.Code)
	}
	if rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "oom", State: "on", TTLMinutes: -5}); rec.Code != http.StatusBadRequest {
		t.Fatalf("negative ttl: want 400, got %d", rec.Code)
	}
	if rec := chaosCall(h, http.MethodPost, "tok", "this is not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: want 400, got %d", rec.Code)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("rejected requests must not reach the cluster, saw %d calls", n)
	}
}

func TestChaosMissingDeploymentReturns404(t *testing.T) {
	r, _ := newChaosReconciler(t, true)
	h := newServer(r, "tok")
	rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "oom", State: "on"})
	if rec.Code != http.StatusNotFound || !bytes.Contains(rec.Body.Bytes(), []byte("not installed")) {
		t.Fatalf("want 404 saying the deployment is not installed, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestChaosWorksWhileDryRunIsTrue(t *testing.T) {
	r, cs := newChaosReconciler(t, true, allChaosDeployments()...)
	r.DryRun = true // DRY_RUN governs remediation, never the chaos switch
	h := newServer(r, "tok")
	if rec := chaosCall(h, http.MethodPost, "tok", ChaosRequest{Scenario: "cpu-spike", State: "on"}); rec.Code != http.StatusOK {
		t.Fatalf("want 200 under DRY_RUN=true, got %d (%s)", rec.Code, rec.Body.String())
	}
	if replicasOf(t, cs, "chaos-cpu-spike") != 1 {
		t.Fatalf("chaos must start even while remediation is dry-run")
	}
}

func TestChaosRejectsOtherMethods(t *testing.T) {
	r, _ := newChaosReconciler(t, true, allChaosDeployments()...)
	h := newServer(r, "tok")
	if rec := chaosCall(h, http.MethodDelete, "tok", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}

func TestChaosWithoutClusterReturns503(t *testing.T) {
	r := NewActionReconciler(nil, nil)
	r.ChaosEnabled = true
	h := newServer(r, "tok")
	if rec := chaosCall(h, http.MethodGet, "tok", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 with no cluster connection, got %d", rec.Code)
	}
}
