package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	log.Println("Aegis-SRE Go action controller starting")

	r, err := buildReconciler()
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	token := os.Getenv("CONTROLLER_TOKEN")
	if token == "" {
		log.Println("WARNING: CONTROLLER_TOKEN is empty; the API is unauthenticated (acceptable only for local development)")
	}
	if r.DryRun {
		log.Println("DRY_RUN=true: actions are validated and reported but never applied")
	} else {
		log.Println("DRY_RUN=false: LIVE mode, actions WILL change the cluster")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, newServer(r, token)))
}

// buildReconciler wires clients and configuration from the environment. Safe defaults:
// dry-run on, replica cap 4, no namespace allowlist (protected namespaces always apply).
func buildReconciler() (*ActionReconciler, error) {
	var r *ActionReconciler
	cfg, err := getKubeConfig()
	if err != nil {
		log.Printf("WARNING: no kubeconfig (%v); running offline in dry-run mode", err)
		r = NewActionReconciler(nil, nil)
	} else {
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("kubernetes client: %w", err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("dynamic client: %w", err)
		}
		r = NewActionReconciler(clientset, dyn)
		r.Exec = newSPDYExec(cfg, clientset)
		log.Println("connected to the Kubernetes API")
	}

	r.DryRun = strings.ToLower(strings.TrimSpace(os.Getenv("DRY_RUN"))) != "false"
	if v := os.Getenv("MAX_REPLICAS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("MAX_REPLICAS must be a positive integer, got %q", v)
		}
		r.MaxReplicas = int32(n)
	}
	if v := os.Getenv("ALLOWED_NAMESPACES"); v != "" {
		r.AllowedNamespaces = map[string]bool{}
		for _, ns := range strings.Split(v, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				r.AllowedNamespaces[ns] = true
			}
		}
	}
	return r, nil
}

func getKubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = fmt.Sprintf("%s/.kube/config", home)
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}
