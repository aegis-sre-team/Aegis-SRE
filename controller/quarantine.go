package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// quarantineLabel marks the one pod a quarantine policy applies to. Cilium endpoint labels do not
// include the pod NAME, so the controller labels the pod and the policy selects that label.
const quarantineLabel = "aegis.io/quarantine-target"

// QuarantineLabelValue returns the label value identifying a pod (<=63 chars).
// Must stay identical to quarantine_label_value in src/controller/cilium_policy.py.
func QuarantineLabelValue(pod string) string {
	if len(pod) <= 63 {
		return pod
	}
	sum := sha256.Sum256([]byte(pod))
	return pod[:52] + "-" + hex.EncodeToString(sum[:])[:10]
}

func quarantinePolicyName(pod string) string { return "aegis-quarantine-" + pod }

// buildQuarantinePolicy returns a CiliumNetworkPolicy that DENIES all ingress and egress for the
// labelled pod. Deny rules win over allow rules from any other policy, and Cilium rejects a rule
// with no rule bodies, so an "empty allow list" would not work.
func buildQuarantinePolicy(namespace, pod, mitre, reason string) *unstructured.Unstructured {
	value := QuarantineLabelValue(pod)
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      quarantinePolicyName(pod),
			"namespace": namespace,
			"labels": map[string]interface{}{
				"app.kubernetes.io/managed-by": "aegis-sre",
				"aegis.io/quarantine":          "true",
				"target-pod":                   value,
			},
			"annotations": map[string]interface{}{
				"aegis.io/managed-by":  "Aegis-SRE-Action-Muscle",
				"aegis.io/action-type": "CILIUM_QUARANTINE_EBPF",
				"aegis.io/status":      "QUARANTINED",
				"aegis.io/mitre-ttp":   mitre,
				"aegis.io/reason":      reason,
			},
		},
		"spec": map[string]interface{}{
			"description":      fmt.Sprintf("Zero-trust quarantine isolating pod %q due to a security threat.", pod),
			"endpointSelector": map[string]interface{}{"matchLabels": map[string]interface{}{quarantineLabel: value}},
			"ingressDeny":      []interface{}{map[string]interface{}{"fromEntities": []interface{}{"all"}}},
			"egressDeny":       []interface{}{map[string]interface{}{"toEntities": []interface{}{"all"}}},
		},
	}}
}

func labelPatch(key string, value interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{"metadata": map[string]interface{}{"labels": map[string]interface{}{key: value}}})
	return b
}

// alreadyQuarantined is true only when BOTH the pod label and the policy exist; if either was
// removed the quarantine is re-applied (with fresh forensics).
func (r *ActionReconciler) alreadyQuarantined(ctx context.Context, pod *corev1.Pod, namespace string) bool {
	if pod.Labels[quarantineLabel] != QuarantineLabelValue(pod.Name) {
		return false
	}
	_, err := r.DynamicClient.Resource(ciliumGVR).Namespace(namespace).Get(ctx, quarantinePolicyName(pod.Name), metav1.GetOptions{})
	return err == nil
}

// quarantine: verify pod -> capture forensics (best effort) -> label pod -> create-or-update deny policy.
// Forensics come first because the isolation must not destroy the evidence, and a forensics failure
// must never block the isolation.
func (r *ActionReconciler) quarantine(ctx context.Context, req ActionRequest, base ActionResult) (ActionResult, error) {
	w, err := r.resolveWorkload(ctx, req.Namespace, req.TargetPod)
	if err != nil {
		return base, err
	}
	if r.alreadyQuarantined(ctx, w.Pod, req.Namespace) {
		// Idempotent and evidence-preserving: do not re-snapshot an already isolated pod, because the
		// first snapshot is the pre-isolation evidence and a second one would describe the cage.
		base.Status, base.Mode = "success", "k8s_cluster"
		base.PolicyName = quarantinePolicyName(req.TargetPod)
		if w.Deployment != nil {
			base.Workload = w.Deployment.Name
		}
		base.Message = fmt.Sprintf("pod %s is already quarantined by %s; nothing changed", req.TargetPod, base.PolicyName)
		return base, nil
	}
	forensics := r.collectForensics(ctx, w.Pod)

	value := QuarantineLabelValue(req.TargetPod)
	if _, err := r.KubeClient.CoreV1().Pods(req.Namespace).Patch(ctx, req.TargetPod, types.MergePatchType, labelPatch(quarantineLabel, value), metav1.PatchOptions{}); err != nil {
		return base, fmt.Errorf("label pod %s/%s: %w", req.Namespace, req.TargetPod, err)
	}

	policy := buildQuarantinePolicy(req.Namespace, req.TargetPod, req.MitreTechnique, req.Reason)
	client := r.DynamicClient.Resource(ciliumGVR).Namespace(req.Namespace)
	existing, err := client.Get(ctx, policy.GetName(), metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := client.Create(ctx, policy, metav1.CreateOptions{}); err != nil {
			return base, fmt.Errorf("create CiliumNetworkPolicy %s: %w", policy.GetName(), err)
		}
	case err != nil:
		return base, fmt.Errorf("get CiliumNetworkPolicy %s: %w", policy.GetName(), err)
	default:
		policy.SetResourceVersion(existing.GetResourceVersion())
		if _, err := client.Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
			return base, fmt.Errorf("update CiliumNetworkPolicy %s: %w", policy.GetName(), err)
		}
	}

	base.Status, base.Mode = "success", "k8s_cluster"
	base.PolicyName = policy.GetName()
	base.Forensics = forensics
	if w.Deployment != nil {
		base.Workload = w.Deployment.Name
	}
	base.Message = fmt.Sprintf("pod %s isolated by CiliumNetworkPolicy %s (forensics captured first)", req.TargetPod, policy.GetName())
	return base, nil
}

// unquarantine removes the policy and the label. It is idempotent: a missing policy or a pod that
// no longer exists is not an error, so a human can always "release" safely.
func (r *ActionReconciler) unquarantine(ctx context.Context, req ActionRequest, base ActionResult) (ActionResult, error) {
	name := quarantinePolicyName(req.TargetPod)
	err := r.DynamicClient.Resource(ciliumGVR).Namespace(req.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return base, fmt.Errorf("delete CiliumNetworkPolicy %s: %w", name, err)
	}

	pod, err := r.KubeClient.CoreV1().Pods(req.Namespace).Get(ctx, req.TargetPod, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// pod already gone: nothing to unlabel
	case err != nil:
		return base, fmt.Errorf("get pod %s/%s: %w", req.Namespace, req.TargetPod, err)
	default:
		if _, has := pod.Labels[quarantineLabel]; has {
			if _, err := r.KubeClient.CoreV1().Pods(req.Namespace).Patch(ctx, req.TargetPod, types.MergePatchType, labelPatch(quarantineLabel, nil), metav1.PatchOptions{}); err != nil {
				return base, fmt.Errorf("unlabel pod %s/%s: %w", req.Namespace, req.TargetPod, err)
			}
		}
	}

	base.Status, base.Mode = "success", "k8s_cluster"
	base.PolicyName = name
	base.Message = fmt.Sprintf("quarantine released for pod %s; network traffic restored", req.TargetPod)
	return base, nil
}
