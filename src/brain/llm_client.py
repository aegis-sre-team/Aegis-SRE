import requests
import json
import os
import logging
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("aegis-brain-llm")

class LLMClient:
    """
    Interfaces with local Ollama (Llama 3.1 8B / 3.2 3B) with automatic
    fallback to Groq / Gemini free cloud API if Ollama is not installed locally.
    """
    def __init__(self, ollama_url: str = None, model_name: str = None):
        self.ollama_url = ollama_url or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model_name = model_name or os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        self.groq_api_key = os.getenv("GROQ_API_KEY", None)

    def generate_json_diagnosis(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Sends prompt to Ollama or fallback cloud LLM and returns parsed JSON verdict.
        """
        # Try local Ollama first
        try:
            target_model = self.model_name
            tags_resp = requests.get(f"{self.ollama_url}/api/tags", timeout=(0.3, 2.0))
            if tags_resp.status_code == 200:
                installed_models = [m.get("name") for m in tags_resp.json().get("models", []) if isinstance(m, dict)]
                if installed_models and target_model not in installed_models:
                    # Pick matching model or first available model
                    matched = [m for m in installed_models if target_model.split(":")[0] in m]
                    target_model = matched[0] if matched else installed_models[0]

            url = f"{self.ollama_url}/api/chat"
            payload = {
                "model": target_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "format": "json",
                "stream": False
            }
            resp = requests.post(url, json=payload, timeout=35)
            if resp.status_code == 200:
                raw_json = resp.json().get("message", {}).get("content", "{}").strip()
                if raw_json.startswith("```"):
                    raw_json = raw_json.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
                start_idx = raw_json.find("{")
                end_idx = raw_json.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    raw_json = raw_json[start_idx:end_idx+1]
                verdict = json.loads(raw_json)
                verdict.setdefault("confidence", 0.0)
                verdict["_ai_provider"] = f"Ollama ({target_model})"
                self._persist_incident_db(verdict)
                return verdict
        except Exception as e:
            logger.warning(f"Ollama AI call failed or unreachable ({e}). Using Aegis Rule-Based Diagnostic Fallback Engine.")

        # Try Cloud Fallback (Groq or Gemini) if configured
        if self.groq_api_key or os.getenv("GEMINI_API_KEY"):
            cloud_verdict = self._try_cloud_llm_fallback(system_prompt, user_prompt)
            if cloud_verdict:
                self._persist_incident_db(cloud_verdict)
                return cloud_verdict

        # Heuristic Rule-Based Diagnostic Engine (Guaranteed zero-dependency fallback)
        verdict = self._rule_based_fallback(user_prompt)
        verdict["_ai_provider"] = "Rule-Based Fallback Engine"
        self._persist_incident_db(verdict)
        return verdict

    def _try_cloud_llm_fallback(self, system_prompt: str, user_prompt: str) -> Optional[dict]:
        """Attempts cloud LLM inference via Groq or Gemini free tiers."""
        # 1. Groq API
        groq_key = self.groq_api_key or os.getenv("GROQ_API_KEY")
        if groq_key:
            groq_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
            for m in [groq_model, "qwen/qwen3.8-27b", "openai/gpt-oss-120b", "llama-3.1-8b-instant"]:
                try:
                    headers = {"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"}
                    payload = {
                        "model": m,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        "response_format": {"type": "json_object"}
                    }
                    resp = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload, timeout=10)
                    if resp.status_code == 200:
                        content = resp.json()["choices"][0]["message"]["content"]
                        data = json.loads(content)
                        data["_ai_provider"] = f"Groq Cloud ({m})"
                        return data
                except Exception as e:
                    logger.debug(f"Groq model {m} attempt failed: {e}")
                    continue

        # 2. Gemini API
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                payload = {
                    "contents": [{
                        "parts": [{"text": f"{system_prompt}\n\nUser Evidence:\n{user_prompt}"}]
                    }],
                    "generationConfig": {"responseMimeType": "application/json"}
                }
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code == 200:
                    text_resp = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                    data = json.loads(text_resp)
                    data["_ai_provider"] = "Google Gemini (gemini-1.5-flash)"
                    return data
            except Exception as e:
                logger.warning(f"Gemini API call failed: {e}")

        return None

    def _rule_based_fallback(self, user_prompt: str) -> dict:
        """
        Deterministic diagnostic fallback matching prompt telemetry keywords.
        Dynamically binds to the target pod identified in prompt evidence.
        """
        import time

        # Extract target pod dynamically from evidence
        target_pod = "aegis-storefront-prod"
        for line in user_prompt.split("\n"):
            clean_line = line.strip()
            if clean_line.lower().startswith("target pod:"):
                target_pod = clean_line.split(":", 1)[1].strip()
                break

        # Inspect evidence section only (before RAG reference runbooks)
        evidence_section = user_prompt.split("[RETRIEVED RAG RUNBOOKS]")[0].lower() if "[RETRIEVED RAG RUNBOOKS]" in user_prompt else user_prompt.lower()

        # Prefer explicit alert_type line so BUG alerts are not overridden by residual wording
        alert_line = ""
        for line in user_prompt.split("\n"):
            if line.strip().lower().startswith("alert event:"):
                alert_line = line.split(":", 1)[1].strip().lower()
                break

        if any(k in alert_line for k in ("falco", "shell", "t1059", "t1552", "security")) or (
            ("t1059" in evidence_section or "security_alert" in evidence_section or "shell spawned" in evidence_section)
            and "oom" not in alert_line
            and "cpu" not in alert_line
            and "aegishighpodcpu" not in alert_line
        ):
            return {
                "incident_id": f"INC-SEC-{int(time.time())}",
                "target_pod": target_pod,
                "problem_type": "SECURITY_ATTACK",
                "threat_level": "CRITICAL",
                "mitre_technique": "T1059 - Command & Scripting Interpreter",
                "root_cause": "Falco eBPF detected unauthorized interactive shell process spawned in container",
                "recommended_action": "CILIUM_QUARANTINE_EBPF",
                "confidence": 0.93,
                "reasoning": (
                    f"MITRE T1059 threat detected on '{target_pod}'. "
                    "Restarting is ineffective; isolate via Cilium eBPF network cage."
                ),
            }

        elif (
            "oom" in alert_line
            or "oom" in evidence_section
            or "near oom" in evidence_section
            or "oom_killed" in evidence_section
        ):
            return {
                "incident_id": f"INC-OOM-{int(time.time())}",
                "target_pod": target_pod,
                "problem_type": "OPERATIONAL_BUG",
                "threat_level": "HIGH",
                "mitre_technique": None,
                "root_cause": f"Memory allocation spike leading to OOMKilled risk on '{target_pod}' (Exit Code 137)",
                "recommended_action": "RESTART_POD",
                "confidence": 0.90,
                "reasoning": (
                    f"Memory usage exceeded cgroup threshold on '{target_pod}'. "
                    "Operational memory leak; triggering pod restart."
                ),
            }

        elif (
            "cpu" in alert_line
            or "aegishighpodcpu" in alert_line
            or "status: elevated" in evidence_section
            or "cpu_quota" in evidence_section
            or "cpu_throttling" in evidence_section
            or "cpu_saturation" in evidence_section
            or "aegishighpodcpu" in evidence_section
        ):
            return {
                "incident_id": f"INC-SCALE-{int(time.time())}",
                "target_pod": target_pod,
                "problem_type": "OPERATIONAL_BUG",
                "threat_level": "HIGH",
                "mitre_technique": None,
                "root_cause": f"Resource quota saturation or elevated CPU detected on '{target_pod}'",
                "recommended_action": "SCALE_DEPLOYMENT",
                "confidence": 0.88,
                "reasoning": (
                    f"Workload demands exceed single replica cgroup quota for '{target_pod}'. "
                    "Triggering horizontal pod scale-out."
                ),
            }

        elif "crashloop" in alert_line:
            # Only the alert line is trusted here (evidence text comes from the workload).
            return {
                "incident_id": f"INC-CRASH-{int(time.time())}",
                "target_pod": target_pod,
                "problem_type": "OPERATIONAL_BUG",
                "threat_level": "HIGH",
                "mitre_technique": None,
                "root_cause": f"Crash loop detected on '{target_pod}' (repeated container restarts)",
                "recommended_action": "RESTART_POD",
                "confidence": 0.80,
                "reasoning": (
                    f"'{target_pod}' keeps restarting. One controlled rollout restart is attempted; the "
                    "per-workload restart budget escalates to a human if it keeps crashing."
                ),
            }

        else:
            return {
                "incident_id": f"INC-SRE-{int(time.time())}",
                "target_pod": target_pod,
                "problem_type": "OPERATIONAL_BUG",
                "threat_level": "MEDIUM",
                "mitre_technique": None,
                "root_cause": f"Operational anomaly on '{target_pod}' without clear security indicators",
                "recommended_action": "RESTART_POD",
                "confidence": 0.75,
                "reasoning": (
                    f"Elevated error / degraded signals for '{target_pod}'. "
                    "Triggering pod restart to clear bad state."
                ),
            }

    def _persist_incident_db(self, verdict: dict):
        """Saves diagnosed incident to SQLite DB."""
        try:
            from src.db.database import SessionLocal, init_db
            from src.db.models import IncidentRecord
            init_db()
            with SessionLocal() as session:
                rec = IncidentRecord(
                    incident_id=verdict.get("incident_id", "INC-AUTO"),
                    target_pod=verdict.get("target_pod", "unknown"),
                    problem_type=verdict.get("problem_type", "UNKNOWN"),
                    threat_level=verdict.get("threat_level", "MEDIUM"),
                    mitre_technique=verdict.get("mitre_technique"),
                    root_cause=verdict.get("root_cause", ""),
                    recommended_action=verdict.get("recommended_action", "ESCALATE"),
                    final_action=verdict.get("recommended_action", "ESCALATE"),
                    confidence=float(verdict.get("confidence", 0.0) or 0.0),
                    status="OPEN"
                )
                session.add(rec)
                session.commit()
        except Exception as e:
            logger.debug(f"SQLite incident persist fallback: {e}")
