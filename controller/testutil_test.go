package main

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const testNS = "online-boutique"

func int32Ptr(i int32) *int32 { return &i }
func boolPtr(b bool) *bool    { return &b }

// boutiqueObjects builds Pod -> ReplicaSet -> Deployment "cartservice" with the given replicas.
func boutiqueObjects(replicas int32) []runtime.Object {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "cartservice", Namespace: testNS, UID: "dep-uid"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(replicas)},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cartservice-6f7d8c9b5", Namespace: testNS, UID: "rs-uid",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "cartservice", UID: "dep-uid", Controller: boolPtr(true)}},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cartservice-6f7d8c9b5-x2k4p", Namespace: testNS,
			Labels:          map[string]string{"app": "cartservice"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "cartservice-6f7d8c9b5", UID: "rs-uid", Controller: boolPtr(true)}},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1", Containers: []corev1.Container{{Name: "server"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.9"},
	}
	return []runtime.Object{dep, rs, pod}
}

func barePod(name, ns string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// ownedPod is a pod controlled by an owner of the given kind (StatefulSet, DaemonSet, Job, ...).
func ownedPod(name, ns, kind string) *corev1.Pod {
	p := barePod(name, ns)
	p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: "owner", UID: "owner-uid", Controller: boolPtr(true)}}
	return p
}

func newTestReconciler(t *testing.T, objs ...runtime.Object) (*ActionReconciler, *fake.Clientset) {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		ciliumGVR: "CiliumNetworkPolicyList",
	})
	r := NewActionReconciler(cs, dyn)
	r.DryRun = false
	return r, cs
}

func mutatingVerbs(actions []clienttesting.Action) []string {
	var out []string
	for _, a := range actions {
		switch a.GetVerb() {
		case "get", "list", "watch":
		default:
			out = append(out, a.GetVerb()+" "+a.GetResource().Resource)
		}
	}
	return out
}

func contextBackground() context.Context { return context.Background() }
