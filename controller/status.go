package main

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DeploymentStatus is the rollout state of the workload that owns a pod.
type DeploymentStatus struct {
	Name               string `json:"name"`
	Desired            int32  `json:"desired"`
	Ready              int32  `json:"ready"`
	Updated            int32  `json:"updated"`
	Replicas           int32  `json:"replicas"`            // all replicas incl. old ones still terminating
	Generation         int64  `json:"generation"`          // latest spec version
	ObservedGeneration int64  `json:"observed_generation"` // spec version the Deployment controller has acted on
}

// PodStatus is what the brain polls to verify that a remediation actually worked.
type PodStatus struct {
	Found       bool   `json:"found"`
	Phase       string `json:"phase,omitempty"`
	Ready       bool   `json:"ready"`
	Restarts    int32  `json:"restarts"`
	Quarantined bool   `json:"quarantined"`
	// Terminating: the pod has a deletionTimestamp. It can still look Running/Ready for its whole grace
	// period, so verification must not mistake the OLD pod for the healthy replacement.
	Terminating bool              `json:"terminating"`
	Deployment  *DeploymentStatus `json:"deployment,omitempty"`
}

// PodSummary is one row of the dashboard's live pod grid.
type PodSummary struct {
	Name        string `json:"name"`
	Phase       string `json:"phase"`
	Ready       bool   `json:"ready"`
	Restarts    int32  `json:"restarts"`
	Node        string `json:"node"`
	IP          string `json:"ip"`
	App         string `json:"app"`
	Quarantined bool   `json:"quarantined"`
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func restartTotal(p *corev1.Pod) int32 {
	var n int32
	for _, cs := range p.Status.ContainerStatuses {
		n += cs.RestartCount
	}
	return n
}

func (r *ActionReconciler) deploymentStatus(ctx context.Context, ns, name string) (*DeploymentStatus, error) {
	dep, err := r.KubeClient.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get deployment %s/%s: %w", ns, name, err)
	}
	desired := int32(1)
	if dep.Spec.Replicas != nil {
		desired = *dep.Spec.Replicas
	}
	return &DeploymentStatus{
		Name: dep.Name, Desired: desired, Ready: dep.Status.ReadyReplicas, Updated: dep.Status.UpdatedReplicas,
		Replicas: dep.Status.Replicas, Generation: dep.Generation, ObservedGeneration: dep.Status.ObservedGeneration,
	}, nil
}

// Status reports the live state of a pod. A pod that no longer exists is reported as found=false
// (not an error): after a rollout restart that is the normal outcome, and deploymentHint lets the
// caller still read the rollout state of the Deployment that replaced it.
func (r *ActionReconciler) Status(ctx context.Context, ns, pod, deploymentHint string) (PodStatus, error) {
	var st PodStatus
	depName := deploymentHint

	w, err := r.resolveWorkload(ctx, ns, pod)
	switch {
	case err == nil:
		st.Found = true
		st.Phase = string(w.Pod.Status.Phase)
		st.Ready = podReady(w.Pod)
		st.Restarts = restartTotal(w.Pod)
		st.Terminating = w.Pod.DeletionTimestamp != nil
		if w.Deployment != nil {
			depName = w.Deployment.Name
		}
		if _, labelled := w.Pod.Labels[quarantineLabel]; labelled {
			if _, perr := r.DynamicClient.Resource(ciliumGVR).Namespace(ns).Get(ctx, quarantinePolicyName(pod), metav1.GetOptions{}); perr == nil {
				st.Quarantined = true
			}
		}
	case isNotFound(err):
		// found stays false
	default:
		return st, err
	}

	if depName != "" {
		ds, derr := r.deploymentStatus(ctx, ns, depName)
		if derr != nil {
			return st, derr
		}
		st.Deployment = ds
	}
	return st, nil
}

// ListPods returns live summaries for one namespace (read-only; powers the dashboard).
func (r *ActionReconciler) ListPods(ctx context.Context, ns string) ([]PodSummary, error) {
	list, err := r.KubeClient.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods in %s: %w", ns, err)
	}
	out := make([]PodSummary, 0, len(list.Items))
	for i := range list.Items {
		p := &list.Items[i]
		_, quarantined := p.Labels[quarantineLabel]
		out = append(out, PodSummary{
			Name: p.Name, Phase: string(p.Status.Phase), Ready: podReady(p), Restarts: restartTotal(p),
			Node: p.Spec.NodeName, IP: p.Status.PodIP, App: p.Labels["app"], Quarantined: quarantined,
		})
	}
	return out, nil
}
