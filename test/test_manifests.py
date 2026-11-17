"""Offline guards for the cluster manifests (no cluster needed)."""
import support  # noqa: F401
import os
import unittest

import yaml

from src.guardrails import PROTECTED_NAMESPACES

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Every (apiGroup, resource, verb) the Go controller actually calls. If the code starts needing
# something new, add it here and to the Role; if the Role loses one, the controller breaks live.
REQUIRED_PERMISSIONS = {
    ("", "pods", "get"), ("", "pods", "list"), ("", "pods", "patch"), ("", "pods", "delete"),
    ("", "pods/log", "get"), ("", "pods/exec", "create"), ("", "events", "list"),
    ("apps", "replicasets", "get"),
    ("apps", "deployments", "get"), ("apps", "deployments", "list"), ("apps", "deployments", "update"),
    ("cilium.io", "ciliumnetworkpolicies", "get"), ("cilium.io", "ciliumnetworkpolicies", "list"),
    ("cilium.io", "ciliumnetworkpolicies", "create"), ("cilium.io", "ciliumnetworkpolicies", "update"),
    ("cilium.io", "ciliumnetworkpolicies", "delete"),
}


def _load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return [d for d in yaml.safe_load_all(f) if d]


def _env(deployment, container=0):
    c = deployment["spec"]["template"]["spec"]["containers"][container]
    return {e["name"]: e for e in c.get("env", [])}


class TestControllerManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = _load("k8s/controller/controller.yaml")
        cls.by_kind = {}
        for d in cls.docs:
            cls.by_kind.setdefault(d["kind"], []).append(d)
        cls.deploy = cls.by_kind["Deployment"][0]

    def test_no_cluster_wide_rbac(self):
        self.assertNotIn("ClusterRole", self.by_kind)
        self.assertNotIn("ClusterRoleBinding", self.by_kind)

    def test_roles_exist_only_in_allowed_namespaces(self):
        allowed = set(_env(self.deploy)["ALLOWED_NAMESPACES"]["value"].split(","))
        role_namespaces = {r["metadata"]["namespace"] for r in self.by_kind["Role"]}
        self.assertEqual(role_namespaces, allowed)
        self.assertFalse(allowed & PROTECTED_NAMESPACES, "allowed namespaces must not include protected ones")

    def test_every_role_grants_what_the_go_code_needs_and_nothing_more_obvious(self):
        for role in self.by_kind["Role"]:
            granted = set()
            for rule in role["rules"]:
                for g in rule["apiGroups"]:
                    for res in rule["resources"]:
                        for v in rule["verbs"]:
                            granted.add((g, res, v))
            missing = REQUIRED_PERMISSIONS - granted
            self.assertFalse(missing, f"{role['metadata']['namespace']}: missing {sorted(missing)}")
            self.assertFalse(any("*" in t for t in granted), "no wildcard permissions")
            self.assertNotIn(("", "secrets", "get"), granted)
            self.assertNotIn(("", "pods", "create"), granted)

    def test_rolebindings_bind_the_controller_service_account_only(self):
        for rb in self.by_kind["RoleBinding"]:
            self.assertEqual(len(rb["subjects"]), 1)
            subj = rb["subjects"][0]
            self.assertEqual((subj["kind"], subj["name"], subj["namespace"]),
                             ("ServiceAccount", "aegis-controller", "aegis-system"))

    def test_controller_defaults_to_dry_run_and_requires_token(self):
        env = _env(self.deploy)
        self.assertEqual(env["DRY_RUN"]["value"], "true")
        self.assertEqual(env["CONTROLLER_TOKEN"]["valueFrom"]["secretKeyRef"]["name"], "aegis-controller-token")
        self.assertNotIn("optional", env["CONTROLLER_TOKEN"]["valueFrom"]["secretKeyRef"])

    def test_controller_container_is_locked_down(self):
        spec = self.deploy["spec"]["template"]["spec"]
        self.assertTrue(spec["securityContext"]["runAsNonRoot"])
        sc = spec["containers"][0]["securityContext"]
        self.assertFalse(sc["allowPrivilegeEscalation"])
        self.assertTrue(sc["readOnlyRootFilesystem"])
        self.assertEqual(sc["capabilities"]["drop"], ["ALL"])

    def test_network_policy_only_admits_brain_and_dashboard(self):
        np = self.by_kind["NetworkPolicy"][0]
        expr = np["spec"]["ingress"][0]["from"][0]["podSelector"]["matchExpressions"][0]
        self.assertEqual(sorted(expr["values"]), ["aegis-brain", "aegis-dashboard"])


class TestBrainManifestWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docs = _load("k8s/brain/brain.yaml")
        cls.deploy = next(d for d in docs if d["kind"] == "Deployment")
        cls.env = _env(cls.deploy)

    def test_brain_stays_dry_run_by_default(self):
        self.assertEqual(self.env["AEGIS_DRY_RUN"]["value"], "true")

    def test_brain_points_at_the_controller_service(self):
        self.assertEqual(
            self.env["GO_CONTROLLER_URL"]["value"],
            "http://aegis-controller.aegis-system.svc:8080/api/v1/reconcile",
        )

    def test_brain_gets_the_controller_token_from_the_same_secret(self):
        ref = self.env["GO_CONTROLLER_TOKEN"]["valueFrom"]["secretKeyRef"]
        self.assertEqual((ref["name"], ref["key"]), ("aegis-controller-token", "token"))

    def test_brain_namespace_allowlist_matches_the_controller(self):
        controller = _load("k8s/controller/controller.yaml")
        cdep = next(d for d in controller if d["kind"] == "Deployment")
        self.assertEqual(self.env["AEGIS_ALLOWED_NAMESPACES"]["value"],
                         _env(cdep)["ALLOWED_NAMESPACES"]["value"])


class TestSensorManifests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docs = _load("k8s/monitoring/prometheus.yaml")
        cm = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "prometheus-rules")
        cls.rules = {}
        for text in cm["data"].values():
            for group in yaml.safe_load(text)["groups"]:
                for rule in group["rules"]:
                    cls.rules[rule["alert"]] = rule
        cls.prom_cfg_text = next(
            d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "prometheus-config"
        )["data"]["prometheus.yml"]

    def test_prometheus_has_oom_and_crashloop_rules_routable_by_alertmanager(self):
        for name in ("AegisHighPodCPU", "AegisContainerOOMKilled", "AegisPodCrashLooping"):
            self.assertIn(name, self.rules)
            rule = self.rules[name]
            self.assertEqual(rule["labels"]["severity"], "warning")  # the AlertManager route matches this
            self.assertEqual(rule["labels"]["aegis_path"], "bug")
            self.assertIn('namespace=~"online-boutique|aegis-chaos"', rule["expr"])
            self.assertIn("summary", rule["annotations"])
            self.assertIn("by (namespace, pod)", rule["expr"], "the webhook needs namespace and pod labels")
        self.assertIn("container_oom_events_total", self.rules["AegisContainerOOMKilled"]["expr"])
        self.assertIn("container_start_time_seconds", self.rules["AegisPodCrashLooping"]["expr"])

    def test_alertmanager_routes_warnings_to_the_brain_webhook(self):
        docs = _load("k8s/monitoring/alertmanager.yaml")
        cm = next(d for d in docs if d["kind"] == "ConfigMap")
        cfg = yaml.safe_load(cm["data"]["alertmanager.yml"])
        self.assertEqual(cfg["receivers"][0]["webhook_configs"][0]["url"],
                         "http://aegis-brain.aegis-system.svc:8001/api/v1/alerts/webhook")
        self.assertIn('severity="warning"', cfg["route"]["routes"][0]["matchers"])

    def test_cadvisor_scrape_verifies_tls(self):
        self.assertNotIn("insecure_skip_verify", self.prom_cfg_text)
        self.assertIn("ca_file", self.prom_cfg_text)

    def test_sensitive_file_rule_ignores_etc_passwd(self):
        # /etc/passwd is read by ordinary programs (id, ls -l, name lookups). Quarantining on it
        # would isolate healthy pods, so only genuinely sensitive credential files may trigger.
        sources = {
            "k8s/monitoring/falco.yaml": None,
            "config/falco/falco_rules.local.yaml": None,
        }
        for path in sources:
            text = open(os.path.join(ROOT, path), encoding="utf-8").read()
            start = text.index("- rule: Aegis Sensitive File Read")
            end = text.index("- rule:", start + 10) if "- rule:" in text[start + 10:] else len(text)
            block = text[start:end]
            condition = block[block.index("condition:"):block.index("output:")]
            self.assertNotIn("/etc/passwd", condition, path)
            self.assertIn("/etc/shadow", condition, path)


if __name__ == "__main__":
    unittest.main()
