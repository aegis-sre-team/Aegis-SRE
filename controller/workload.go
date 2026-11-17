package main

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// workload is a pod together with the Deployment that owns it (nil for bare/StatefulSet/DaemonSet pods).
type workload struct {
	Pod        *corev1.Pod
	Deployment *appsv1.Deployment
}

func ownerOfKind(refs []metav1.OwnerReference, kind string) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Kind == kind {
			return &refs[i]
		}
	}
	return nil
}

// hasRestartableController is true when a controller that recreates deleted pods owns the pod.
func hasRestartableController(p *corev1.Pod) bool {
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller && (o.Kind == "ReplicaSet" || o.Kind == "StatefulSet" || o.Kind == "DaemonSet") {
			return true
		}
	}
	return false
}

// resolveWorkload follows Pod -> ReplicaSet -> Deployment using real owner references, instead of
// guessing the Deployment from the pod name.
func (r *ActionReconciler) resolveWorkload(ctx context.Context, ns, podName string) (*workload, error) {
	pod, err := r.KubeClient.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: pod %s/%s", ErrNotFound, ns, podName)
	}
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	w := &workload{Pod: pod}
	rsRef := ownerOfKind(pod.OwnerReferences, "ReplicaSet")
	if rsRef == nil {
		return w, nil
	}
	rs, err := r.KubeClient.AppsV1().ReplicaSets(ns).Get(ctx, rsRef.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return w, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get replicaset %s/%s: %w", ns, rsRef.Name, err)
	}
	depRef := ownerOfKind(rs.OwnerReferences, "Deployment")
	if depRef == nil {
		return w, nil
	}
	dep, err := r.KubeClient.AppsV1().Deployments(ns).Get(ctx, depRef.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return w, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get deployment %s/%s: %w", ns, depRef.Name, err)
	}
	w.Deployment = dep
	return w, nil
}

// restart performs a rollout restart of the owning Deployment (same semantics as
// `kubectl rollout restart`); a pod with no Deployment is simply deleted so its controller recreates it.
func (r *ActionReconciler) restart(ctx context.Context, req ActionRequest, base ActionResult) (ActionResult, error) {
	w, err := r.resolveWorkload(ctx, req.Namespace, req.TargetPod)
	if err != nil {
		return base, err
	}
	if w.Deployment == nil {
		if !hasRestartableController(w.Pod) {
			// Deleting a pod nothing will recreate (bare pod, Job pod) is data loss, not a restart.
			return base, fmt.Errorf("%w: pod %s/%s has no ReplicaSet/StatefulSet/DaemonSet controller to recreate it",
				ErrNoWorkload, req.Namespace, req.TargetPod)
		}
		if err := r.KubeClient.CoreV1().Pods(req.Namespace).Delete(ctx, req.TargetPod, metav1.DeleteOptions{}); err != nil {
			return base, fmt.Errorf("delete pod %s/%s: %w", req.Namespace, req.TargetPod, err)
		}
		base.Status, base.Mode = "success", "k8s_cluster"
		base.Message = fmt.Sprintf("pod %s has no Deployment; deleted so its controller recreates it", req.TargetPod)
		return base, nil
	}
	name := w.Deployment.Name
	stamp := r.now().UTC().Format(time.RFC3339)
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, getErr := r.KubeClient.AppsV1().Deployments(req.Namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if dep.Spec.Template.Annotations == nil {
			dep.Spec.Template.Annotations = map[string]string{}
		}
		dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = stamp
		_, updErr := r.KubeClient.AppsV1().Deployments(req.Namespace).Update(ctx, dep, metav1.UpdateOptions{})
		return updErr
	})
	if err != nil {
		return base, fmt.Errorf("rollout restart deployment %s/%s: %w", req.Namespace, name, err)
	}
	base.Status, base.Mode = "success", "k8s_cluster"
	base.Workload = name
	base.Message = fmt.Sprintf("rollout restart triggered for deployment %s (pod %s)", name, req.TargetPod)
	return base, nil
}

// scale adds a replica (or sets req.Replicas), never exceeding MaxReplicas.
func (r *ActionReconciler) scale(ctx context.Context, req ActionRequest, base ActionResult) (ActionResult, error) {
	w, err := r.resolveWorkload(ctx, req.Namespace, req.TargetPod)
	if err != nil {
		return base, err
	}
	if w.Deployment == nil {
		return base, fmt.Errorf("%w: %s/%s", ErrNoWorkload, req.Namespace, req.TargetPod)
	}
	name := w.Deployment.Name
	limit := r.MaxReplicas
	if limit <= 0 {
		limit = 4
	}
	var from, to int32
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, getErr := r.KubeClient.AppsV1().Deployments(req.Namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		from = 1
		if dep.Spec.Replicas != nil {
			from = *dep.Spec.Replicas
		}
		to = from + 1
		if req.Replicas != nil {
			to = *req.Replicas
		}
		if to > limit {
			to = limit
		}
		if to == from {
			return nil // already at the cap (or already at the requested size)
		}
		dep.Spec.Replicas = &to
		_, updErr := r.KubeClient.AppsV1().Deployments(req.Namespace).Update(ctx, dep, metav1.UpdateOptions{})
		return updErr
	})
	if err != nil {
		return base, fmt.Errorf("scale deployment %s/%s: %w", req.Namespace, name, err)
	}
	base.Status, base.Mode = "success", "k8s_cluster"
	base.Workload = name
	if to == from {
		base.Message = fmt.Sprintf("deployment %s already at %d replicas (cap %d); nothing to do", name, from, limit)
	} else {
		base.Message = fmt.Sprintf("deployment %s scaled %d -> %d replicas (cap %d)", name, from, to, limit)
	}
	return base, nil
}
