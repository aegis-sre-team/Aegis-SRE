package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	maxLogContainers = 3
	logTailLines     = 200
	maxEvents        = 20
)

// ExecFunc runs a command inside a container and returns its stdout. It is optional and
// best-effort: a nil ExecFunc simply means "no process list in the forensics snapshot".
type ExecFunc func(ctx context.Context, namespace, pod, container string, cmd []string) (string, error)

// ContainerSummary is the per-container state captured at snapshot time.
type ContainerSummary struct {
	Name         string `json:"name"`
	Image        string `json:"image"`
	Ready        bool   `json:"ready"`
	RestartCount int32  `json:"restart_count"`
	State        string `json:"state"`
}

// Forensics is a real DFIR snapshot of a pod, captured BEFORE it is isolated. Anything that
// could not be collected is listed in Errors; nothing is invented.
type Forensics struct {
	CapturedAt        string              `json:"captured_at"`
	Pod               string              `json:"pod"`
	Namespace         string              `json:"namespace"`
	Phase             string              `json:"phase"`
	NodeName          string              `json:"node_name"`
	PodIP             string              `json:"pod_ip"`
	Labels            map[string]string   `json:"labels"`
	ContainerStatuses []ContainerSummary  `json:"container_statuses"`
	Events            []string            `json:"events"`
	Logs              map[string][]string `json:"logs"`
	ProcessList       *string             `json:"process_list"`
	Errors            []string            `json:"errors"`
}

func containerState(s corev1.ContainerState) string {
	switch {
	case s.Running != nil:
		return "running"
	case s.Waiting != nil:
		return "waiting:" + s.Waiting.Reason
	case s.Terminated != nil:
		return "terminated:" + s.Terminated.Reason
	}
	return "unknown"
}

// collectForensics gathers pod facts, events, log tails and (if configured) a process list.
// It never returns an error: failures are recorded in Forensics.Errors so isolation can proceed.
func (r *ActionReconciler) collectForensics(ctx context.Context, pod *corev1.Pod) *Forensics {
	f := &Forensics{
		CapturedAt:        r.now().UTC().Format(time.RFC3339),
		Pod:               pod.Name,
		Namespace:         pod.Namespace,
		Phase:             string(pod.Status.Phase),
		NodeName:          pod.Spec.NodeName,
		PodIP:             pod.Status.PodIP,
		Labels:            pod.Labels,
		ContainerStatuses: []ContainerSummary{},
		Events:            []string{},
		Logs:              map[string][]string{},
		Errors:            []string{},
	}

	seen := map[string]bool{}
	for _, cs := range pod.Status.ContainerStatuses {
		seen[cs.Name] = true
		f.ContainerStatuses = append(f.ContainerStatuses, ContainerSummary{
			Name: cs.Name, Image: cs.Image, Ready: cs.Ready, RestartCount: cs.RestartCount, State: containerState(cs.State),
		})
	}
	for _, c := range pod.Spec.Containers {
		if !seen[c.Name] {
			f.ContainerStatuses = append(f.ContainerStatuses, ContainerSummary{Name: c.Name, Image: c.Image, State: "unknown"})
		}
	}

	// Events: filter client-side as well; do not rely on the server honouring the field selector.
	evs, err := r.KubeClient.CoreV1().Events(pod.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + pod.Name,
	})
	if err != nil {
		f.Errors = append(f.Errors, fmt.Sprintf("events: %v", err))
	} else {
		items := evs.Items
		sort.SliceStable(items, func(i, j int) bool { return items[i].LastTimestamp.Before(&items[j].LastTimestamp) })
		for _, e := range items {
			if e.InvolvedObject.Name != pod.Name {
				continue
			}
			f.Events = append(f.Events, fmt.Sprintf("%s %s: %s", e.Type, e.Reason, e.Message))
		}
		if len(f.Events) > maxEvents {
			f.Events = f.Events[len(f.Events)-maxEvents:]
		}
	}

	tail := int64(logTailLines)
	for i, c := range pod.Spec.Containers {
		if i >= maxLogContainers {
			break
		}
		raw, err := r.KubeClient.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: c.Name, TailLines: &tail}).DoRaw(ctx)
		if err != nil {
			f.Errors = append(f.Errors, fmt.Sprintf("logs %s: %v", c.Name, err))
			continue
		}
		f.Logs[c.Name] = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}

	switch {
	case r.Exec == nil:
		f.Errors = append(f.Errors, "exec: not configured; process list unavailable")
	case len(pod.Spec.Containers) == 0:
		f.Errors = append(f.Errors, "exec: pod has no containers")
	default:
		container := pod.Spec.Containers[0].Name
		var lastErr error
		for _, cmd := range [][]string{{"ps", "aux"}, {"ps"}} {
			out, err := r.Exec(ctx, pod.Namespace, pod.Name, container, cmd)
			if err == nil {
				f.ProcessList = &out
				lastErr = nil
				break
			}
			lastErr = err
		}
		if lastErr != nil {
			f.Errors = append(f.Errors, fmt.Sprintf("exec: %v", lastErr))
		}
	}
	return f
}
