import support  # noqa: F401
import glob
import os
import unittest

import yaml

CHAOS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "k8s", "chaos")

# Must match chaosScenarios in controller/chaos.go: the controller only starts these Deployments.
EXPECTED_DEPLOYMENTS = {
    "chaos-cpu-spike", "chaos-oom", "chaos-crashloop", "chaos-http-500", "chaos-shell-injection",
    "chaos-credential-read", "chaos-network-recon", "chaos-restart-storm",
}


def _deployments():
    out = {}
    for path in sorted(glob.glob(os.path.join(CHAOS_DIR, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            for doc in yaml.safe_load_all(f):
                if doc and doc.get("kind") == "Deployment":
                    out[doc["metadata"]["name"]] = doc
    return out


class TestChaosManifests(unittest.TestCase):
    def test_every_scenario_manifest_is_present_and_safe(self):
        deployments = _deployments()
        self.assertEqual(EXPECTED_DEPLOYMENTS, set(deployments), "chaos manifests must match the controller allowlist")
        for name, dep in deployments.items():
            with self.subTest(deployment=name):
                self.assertEqual("aegis-chaos", dep["metadata"]["namespace"])
                self.assertEqual(0, dep["spec"]["replicas"], "scenarios rest at 0 replicas")
                pod = dep["spec"]["template"]["spec"]
                self.assertFalse(pod.get("hostNetwork"), "no host network")
                self.assertFalse(pod.get("hostPID"), "no host PID")
                self.assertFalse(
                    [v for v in pod.get("volumes", []) if "secret" in v], "no secret volumes")
                self.assertFalse(pod.get("automountServiceAccountToken", False), "no service account token")
                for c in pod["containers"]:
                    self.assertIn("memory", (c.get("resources") or {}).get("limits", {}), "memory limit required")
                    self.assertFalse((c.get("securityContext") or {}).get("privileged"), "never privileged")

    def test_new_scenarios_carry_the_labels_the_ui_and_runbooks_expect(self):
        deployments = _deployments()
        for name in ("chaos-credential-read", "chaos-network-recon", "chaos-restart-storm"):
            labels = deployments[name]["spec"]["template"]["metadata"]["labels"]
            with self.subTest(deployment=name):
                self.assertEqual(name, labels.get("app"))
                self.assertIn("aegis.io/chaos", labels)


FALCO_YAML = os.path.join(os.path.dirname(CHAOS_DIR), "monitoring", "falco.yaml")


class TestFalcoConfig(unittest.TestCase):
    def test_every_matching_rule_may_fire(self):
        """Falco defaults to rule_matching=first: an event caught by a built-in rule (e.g. 'Read sensitive file
        untrusted' for /etc/shadow) would never reach the Aegis rule that the brain listens for."""
        with open(FALCO_YAML, encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
        cfg = next(d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "falco-config")
        falco = yaml.safe_load(cfg["data"]["falco.yaml"])
        self.assertEqual("all", falco.get("rule_matching"))


if __name__ == "__main__":
    unittest.main()
