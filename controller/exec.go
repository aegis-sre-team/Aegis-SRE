package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// newSPDYExec returns an ExecFunc that runs a command in a container over the Kubernetes exec API
// (same mechanism as `kubectl exec`). It is only exercised against a live cluster; unit tests
// inject a fake ExecFunc instead. Every call is bounded by a 5s timeout.
func newSPDYExec(cfg *rest.Config, cs kubernetes.Interface) ExecFunc {
	return func(ctx context.Context, namespace, pod, container string, cmd []string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		req := cs.CoreV1().RESTClient().Post().
			Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: container, Command: cmd, Stdout: true, Stderr: true,
			}, scheme.ParameterCodec)

		executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
		if err != nil {
			return "", fmt.Errorf("exec setup: %w", err)
		}
		var stdout, stderr bytes.Buffer
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
			return "", fmt.Errorf("exec %s: %w (%s)", strings.Join(cmd, " "), err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	}
}
