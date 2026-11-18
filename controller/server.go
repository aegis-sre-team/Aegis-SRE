package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
)

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// httpStatusFor maps a Reconcile error to an HTTP status code.
func httpStatusFor(err error) int {
	switch {
	case errors.Is(err, ErrProtectedNamespace), errors.Is(err, ErrNamespaceNotAllowed), errors.Is(err, ErrChaosDisabled):
		return http.StatusForbidden
	case errors.Is(err, ErrNamespaceRequired), errors.Is(err, ErrUnsupportedAction), errors.Is(err, ErrInvalidTarget), errors.Is(err, ErrInvalidReplicas),
		errors.Is(err, ErrUnknownScenario), errors.Is(err, ErrInvalidChaosState), errors.Is(err, ErrInvalidTTL):
		return http.StatusBadRequest
	case errors.Is(err, ErrNoCluster):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrNoWorkload):
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]interface{}{"status": "error", "error": msg})
}

// newServer builds the HTTP API. When token is non-empty every route except /healthz requires
// "Authorization: Bearer <token>" (compared in constant time).
func newServer(r *ActionReconciler, token string) http.Handler {
	mux := http.NewServeMux()

	protect := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if token != "" {
				got, hasScheme := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
				if !hasScheme || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
					writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
					return
				}
			}
			h(w, req)
		}
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "healthy", "service": "aegis-go-controller",
			"dry_run": r.DryRun, "cluster_connected": r.KubeClient != nil,
		})
	})

	mux.HandleFunc("/api/v1/reconcile", protect(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}
		var in ActionRequest
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
			return
		}
		res, err := r.Reconcile(req.Context(), in)
		switch {
		case errors.Is(err, ErrNotApproved):
			log.Printf("[SKIP] %s on %s/%s not approved by guardrails", in.FinalAction, in.Namespace, in.TargetPod)
			res.Status, res.Message = "skipped", "action not approved by guardrails; nothing done"
			writeJSON(w, http.StatusOK, res)
		case err != nil:
			log.Printf("[ERROR] %s on %s/%s: %v", in.FinalAction, in.Namespace, in.TargetPod, err)
			writeJSON(w, httpStatusFor(err), map[string]interface{}{
				"status": "error", "error": err.Error(), "action": in.FinalAction, "target": in.TargetPod, "namespace": in.Namespace,
			})
		default:
			writeJSON(w, http.StatusOK, res)
		}
	}))

	// Chaos controls: start/stop the fixed failure-injection scenarios (see chaos.go). Off unless
	// CHAOS_ENABLED=true; independent of DRY_RUN.
	mux.HandleFunc("/api/v1/chaos", protect(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			list, err := r.ListChaos(req.Context())
			if err != nil {
				writeError(w, httpStatusFor(err), err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"scenarios": list})
		case http.MethodPost:
			var in ChaosRequest
			if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
				return
			}
			res, err := r.SetChaos(req.Context(), in)
			if err != nil {
				writeError(w, httpStatusFor(err), err.Error())
				return
			}
			writeJSON(w, http.StatusOK, res)
		default:
			writeError(w, http.StatusMethodNotAllowed, "GET or POST required")
		}
	}))

	mux.HandleFunc("/api/v1/status", protect(func(w http.ResponseWriter, req *http.Request) {
		ns, pod := req.URL.Query().Get("namespace"), req.URL.Query().Get("pod")
		if ns == "" || pod == "" {
			writeError(w, http.StatusBadRequest, "namespace and pod are required")
			return
		}
		if r.KubeClient == nil {
			writeError(w, http.StatusServiceUnavailable, "no cluster connection")
			return
		}
		st, err := r.Status(req.Context(), ns, pod, req.URL.Query().Get("deployment"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st)
	}))

	mux.HandleFunc("/api/v1/pods", protect(func(w http.ResponseWriter, req *http.Request) {
		ns := req.URL.Query().Get("namespace")
		if ns == "" {
			writeError(w, http.StatusBadRequest, "namespace is required")
			return
		}
		if r.KubeClient == nil {
			writeError(w, http.StatusServiceUnavailable, "no cluster connection")
			return
		}
		pods, err := r.ListPods(req.Context(), ns)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"namespace": ns, "pods": pods})
	}))

	return mux
}
