package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// Chaos controls start and stop the fixed set of failure-injection Deployments that ship in
// k8s/chaos/. They are deliberately narrow: one namespace, a fixed allowlist, nothing taken from a
// request except which scenario and on/off. They are gated by CHAOS_ENABLED, never by DRY_RUN:
// DRY_RUN governs remediation, and chaos is the thing being remediated.
const (
	chaosNamespace         = "aegis-chaos"
	chaosExpiresAnnotation = "aegis.io/chaos-expires-at" // RFC 3339, UTC
	defaultChaosTTL        = 30                          // minutes
	maxChaosTTL            = 120                         // minutes
)

// chaosScenarios maps a scenario id to its Deployment in chaosNamespace.
var chaosScenarios = map[string]string{
	"cpu-spike":       "chaos-cpu-spike",
	"oom":             "chaos-oom",
	"crashloop":       "chaos-crashloop",
	"http-500":        "chaos-http-500",
	"shell-injection": "chaos-shell-injection",
	"credential-read": "chaos-credential-read",
	"network-recon":   "chaos-network-recon",
	"restart-storm":   "chaos-restart-storm",
}

// ChaosScenario is one scenario and its current state.
type ChaosScenario struct {
	ID         string `json:"id"`
	Deployment string `json:"deployment"`
	Installed  bool   `json:"installed"` // false when the manifest has not been applied
	Replicas   int32  `json:"replicas"`
	Ready      int32  `json:"ready"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// ChaosRequest turns a scenario on or off. TTLMinutes applies to "on" only (0 = default).
type ChaosRequest struct {
	Scenario   string `json:"scenario"`
	State      string `json:"state"`
	TTLMinutes int    `json:"ttl_minutes,omitempty"`
}

func sortedScenarioIDs() []string {
	ids := make([]string, 0, len(chaosScenarios))
	for id := range chaosScenarios {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func describeChaos(id string, dep *appsv1.Deployment) ChaosScenario {
	s := ChaosScenario{ID: id, Deployment: chaosScenarios[id]}
	if dep == nil {
		return s
	}
	s.Installed = true
	if dep.Spec.Replicas != nil {
		s.Replicas = *dep.Spec.Replicas
	}
	s.Ready = dep.Status.ReadyReplicas
	s.ExpiresAt = dep.Annotations[chaosExpiresAnnotation]
	return s
}

func (r *ActionReconciler) chaosGate() error {
	if !r.ChaosEnabled {
		return ErrChaosDisabled
	}
	if r.KubeClient == nil {
		return ErrNoCluster
	}
	return nil
}

// getChaosDeployment fetches a scenario's Deployment; a missing one wraps ErrNotFound.
func (r *ActionReconciler) getChaosDeployment(ctx context.Context, id string) (*appsv1.Deployment, error) {
	name := chaosScenarios[id]
	dep, err := r.KubeClient.AppsV1().Deployments(chaosNamespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: deployment %s/%s is not installed (apply k8s/chaos/)", ErrNotFound, chaosNamespace, name)
	}
	return dep, err
}

// ListChaos reports every scenario, sorted by id. A scenario whose manifest has not been applied
// is reported as Installed=false rather than failing the whole list.
func (r *ActionReconciler) ListChaos(ctx context.Context) ([]ChaosScenario, error) {
	if err := r.chaosGate(); err != nil {
		return nil, err
	}
	out := make([]ChaosScenario, 0, len(chaosScenarios))
	for _, id := range sortedScenarioIDs() {
		dep, err := r.getChaosDeployment(ctx, id)
		switch {
		case err == nil:
			out = append(out, describeChaos(id, dep))
		case chaosMissing(err):
			out = append(out, describeChaos(id, nil))
		default:
			return nil, err
		}
	}
	return out, nil
}

// SetChaos starts ("on": 1 replica plus an expiry) or stops ("off": 0 replicas, expiry removed) a scenario.
// Both directions are idempotent; starting again refreshes the expiry.
func (r *ActionReconciler) SetChaos(ctx context.Context, req ChaosRequest) (ChaosScenario, error) {
	if err := r.chaosGate(); err != nil {
		return ChaosScenario{}, err
	}
	if _, ok := chaosScenarios[req.Scenario]; !ok {
		return ChaosScenario{}, fmt.Errorf("%w: %q", ErrUnknownScenario, req.Scenario)
	}
	if req.State != "on" && req.State != "off" {
		return ChaosScenario{}, fmt.Errorf("%w: got %q", ErrInvalidChaosState, req.State)
	}
	ttl := req.TTLMinutes
	if req.State == "on" {
		switch {
		case ttl < 0:
			return ChaosScenario{}, ErrInvalidTTL
		case ttl == 0:
			ttl = defaultChaosTTL
		case ttl > maxChaosTTL:
			ttl = maxChaosTTL
		}
	}

	// The Deployment controller rewrites status constantly, so a plain Get+Update can lose the race
	// ("the object has been modified"). Re-read and try again on conflict.
	var updated *appsv1.Deployment
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, err := r.getChaosDeployment(ctx, req.Scenario)
		if err != nil {
			return err
		}
		if req.State == "on" {
			one := int32(1)
			dep.Spec.Replicas = &one
			if dep.Annotations == nil {
				dep.Annotations = map[string]string{}
			}
			dep.Annotations[chaosExpiresAnnotation] = r.now().UTC().Add(time.Duration(ttl) * time.Minute).Format(time.RFC3339)
		} else {
			zero := int32(0)
			dep.Spec.Replicas = &zero
			delete(dep.Annotations, chaosExpiresAnnotation)
		}
		updated, err = r.KubeClient.AppsV1().Deployments(chaosNamespace).Update(ctx, dep, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return ChaosScenario{}, err
	}
	log.Printf("[CHAOS] %s turned %s (deployment %s/%s)", req.Scenario, req.State, chaosNamespace, chaosScenarios[req.Scenario])
	return describeChaos(req.Scenario, updated), nil
}

// StopExpiredChaos stops every running scenario whose time limit has passed. A running scenario with a
// missing or unparsable expiry is treated as expired: when in doubt, stop. Returns how many it stopped.
func (r *ActionReconciler) StopExpiredChaos(ctx context.Context) (int, error) {
	if !r.ChaosEnabled || r.KubeClient == nil {
		return 0, nil
	}
	stopped := 0
	for _, id := range sortedScenarioIDs() {
		dep, err := r.getChaosDeployment(ctx, id)
		if chaosMissing(err) {
			continue
		}
		if err != nil {
			return stopped, err
		}
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas == 0 {
			continue
		}
		if until, perr := time.Parse(time.RFC3339, dep.Annotations[chaosExpiresAnnotation]); perr == nil && r.now().Before(until) {
			continue
		}
		if _, err := r.SetChaos(ctx, ChaosRequest{Scenario: id, State: "off"}); err != nil {
			return stopped, err
		}
		stopped++
	}
	return stopped, nil
}

// RunChaosJanitor stops expired scenarios every `every` until ctx is cancelled, so the time limit
// survives a dashboard or UI restart.
func (r *ActionReconciler) RunChaosJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := r.StopExpiredChaos(ctx); err != nil {
				log.Printf("[CHAOS] janitor: %v", err)
			} else if n > 0 {
				log.Printf("[CHAOS] janitor stopped %d expired scenario(s)", n)
			}
		}
	}
}

func chaosMissing(err error) bool { return errors.Is(err, ErrNotFound) }
