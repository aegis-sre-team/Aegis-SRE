import hashlib
import json
import yaml
from typing import Dict, Any, Optional

# Pods are isolated by labelling them and selecting that label in the policy. Cilium endpoint
# labels do not include the pod *name*, so selecting on a name-like label would match nothing.
QUARANTINE_LABEL = "aegis.io/quarantine-target"
_LABEL_VALUE_MAX = 63


def quarantine_label_value(pod_name: str) -> str:
    """Label value identifying one pod. Must stay identical to QuarantineLabelValue in controller/.

    Kubernetes label values are capped at 63 chars. Longer names keep their first 52 chars plus
    '-' plus the first 10 hex chars of sha256(name), which stays unique and deterministic.
    """
    if len(pod_name) <= _LABEL_VALUE_MAX:
        return pod_name
    return f"{pod_name[:52]}-{hashlib.sha256(pod_name.encode()).hexdigest()[:10]}"


class CiliumPolicyGenerator:
    """
    Cilium eBPF & Kubernetes Network Policy Generator (Phase 5).
    Generates zero-trust isolation policies to drop 100% of ingress and egress network traffic
    for compromised pods identified by security alerts (e.g. Falco MITRE ATT&CK rules).
    """

    @staticmethod
    def generate_cilium_quarantine_policy(
        pod_name: str,
        namespace: str = "default",
        app_label: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates a CiliumNetworkPolicy (cilium.io/v2) manifest for kernel-level eBPF isolation.
        ingressDeny/egressDeny on the "all" entity drop every packet to/from the labelled pod.
        """
        target_app = app_label if app_label else pod_name
        policy_name = f"aegis-quarantine-{pod_name}"

        annotations = {
            "aegis.io/managed-by": "Aegis-SRE-Action-Muscle",
            "aegis.io/action-type": "CILIUM_QUARANTINE_EBPF",
            "aegis.io/status": "QUARANTINED"
        }
        if mitre_technique:
            annotations["aegis.io/mitre-ttp"] = mitre_technique
        if reason:
            annotations["aegis.io/reason"] = reason

        match_labels = {QUARANTINE_LABEL: quarantine_label_value(pod_name)}

        # Explicit deny rules (not an empty allow-list): deny always wins over allow rules from
        # other policies, and Cilium rejects a rule that has no ingress/egress rule bodies.
        policy_spec = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "aegis-sre",
                    "aegis.io/quarantine": "true",
                    "target-pod": quarantine_label_value(pod_name)
                },
                "annotations": annotations
            },
            "spec": {
                "description": f"Zero-trust eBPF quarantine isolating pod '{pod_name}' due to security threat detection.",
                "endpointSelector": {
                    "matchLabels": match_labels
                },
                "ingressDeny": [{"fromEntities": ["all"]}],
                "egressDeny": [{"toEntities": ["all"]}]
            }
        }
        return policy_spec

    @staticmethod
    def generate_k8s_standard_quarantine_policy(
        pod_name: str,
        namespace: str = "default",
        app_label: Optional[str] = None,
        mitre_technique: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates a standard Kubernetes NetworkPolicy (networking.k8s.io/v1) manifest
        as a fallback if Cilium CRDs are not registered on the cluster.
        """
        target_app = app_label if app_label else pod_name
        policy_name = f"aegis-k8s-quarantine-{pod_name}"

        policy_spec = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "aegis-sre",
                    "aegis.io/quarantine": "true"
                }
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app": target_app
                    }
                },
                "policyTypes": [
                    "Ingress",
                    "Egress"
                ]
                # Omitting ingress and egress sections defaults to DENY ALL for both
            }
        }
        return policy_spec

    @staticmethod
    def generate_unquarantine_spec(
        pod_name: str,
        namespace: str = "default"
    ) -> Dict[str, Any]:
        """
        Generates removal metadata specification for removing a quarantine policy and restoring traffic.
        """
        policy_name = f"aegis-quarantine-{pod_name}"
        return {
            "policy_name": policy_name,
            "namespace": namespace,
            "target_pod": pod_name,
            "action": "UNQUARANTINE_POD",
            "command": f"kubectl delete ciliumnetworkpolicy {policy_name} -n {namespace}",
            "label_to_remove": QUARANTINE_LABEL
        }

    @classmethod
    def to_yaml(cls, policy_spec: Dict[str, Any]) -> str:
        """Serializes policy spec dictionary to clean YAML format."""
        return yaml.dump(policy_spec, sort_keys=False, default_flow_style=False)

    @classmethod
    def to_json(cls, policy_spec: Dict[str, Any]) -> str:
        """Serializes policy spec dictionary to JSON format."""
        return json.dumps(policy_spec, indent=2)
