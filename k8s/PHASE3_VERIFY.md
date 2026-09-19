# Phase 3 verify — Diagnostic Brain on oracle-k3s
#
# Prerequisites: Phase 1–2 green; image `aegis-brain:phase3` imported on the node.
#
# Apply:
#   kubectl config use-context oracle-k3s
#   kubectl apply -f k8s/00-namespace.yaml
#   kubectl -n aegis-system create secret generic aegis-brain-secrets \
#     --from-literal=GROQ_API_KEY="$GROQ_API_KEY" \
#     --from-literal=GROQ_MODEL="${GROQ_MODEL:-openai/gpt-oss-20b}" \
#     --dry-run=client -o yaml | kubectl apply -f -
#   kubectl apply -f k8s/brain/brain.yaml
#   kubectl apply -f k8s/monitoring/alertmanager.yaml
#
# Checks:
#   kubectl get pods -n aegis-system
#   kubectl port-forward -n aegis-system svc/aegis-brain 8001:8001
#   curl http://127.0.0.1:8001/health
#   curl -X POST http://127.0.0.1:8001/api/v1/diagnose \
#     -H 'Content-Type: application/json' \
#     -d '{"pod_name":"chaos-shell-injection","alert_type":"falco_shell_spawn"}'
