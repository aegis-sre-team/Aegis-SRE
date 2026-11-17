/* ==========================================================================
   AEGIS-SRE // MISSION CONTROL DASHBOARD JAVASCRIPT APPLICATION
   Manages WebSockets telemetry, DOM updates, DFIR modal, HITL drawer, & chaos triggers.
   ========================================================================== */

let socket = null;
let currentActiveEscalation = null;

let fallbackInterval = null;

document.addEventListener("DOMContentLoaded", () => {
    fetchInitialState();
    initWebSocket();
});

async function fetchInitialState() {
    try {
        const resp = await fetch("/api/v1/telemetry/state");
        const data = await resp.json();
        handleServerEvent(data);
    } catch (e) {
        console.error("Initial REST fetch error:", e);
    }
}

function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        appendTerminalLog("SUCCESS", "WEBSOCKET", "Connected to Aegis Mission Control real-time telemetry stream.");
        if (fallbackInterval) {
            clearInterval(fallbackInterval);
            fallbackInterval = null;
        }
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleServerEvent(data);
        } catch (e) {
            console.error("Error parsing WebSocket message:", e);
        }
    };

    socket.onclose = () => {
        appendTerminalLog("WARN", "WEBSOCKET", "Connection dropped. Using HTTP REST fallback stream...");
        if (!fallbackInterval) {
            fallbackInterval = setInterval(fetchInitialState, 2000);
        }
        setTimeout(initWebSocket, 3000);
    };

    socket.onerror = (err) => {
        console.error("WebSocket error:", err);
    };
}

// Mutating endpoints may require AEGIS_DASHBOARD_TOKEN. The token is asked for once and kept in this
// browser's localStorage; read-only endpoints never need it.
async function authFetch(url, opts = {}) {
    const withToken = (token) => ({
        ...opts,
        headers: { ...(opts.headers || {}), ...(token ? { "X-Aegis-Token": token } : {}) },
    });
    let token = null;
    try { token = localStorage.getItem("aegisToken"); } catch (e) { /* storage unavailable */ }
    let resp = await fetch(url, withToken(token));
    if (resp.status === 401) {
        const entered = window.prompt("This action requires the dashboard token:");
        if (entered) {
            try { localStorage.setItem("aegisToken", entered); } catch (e) { /* ignore */ }
            resp = await fetch(url, withToken(entered));
        }
    }
    return resp;
}

function setPill(id, label, ok, upText, downText) {
    const el = document.getElementById(id);
    if (!el) return;
    el.querySelector(".pill-text").innerText = `${label}: ${ok === true ? upText : downText}`;
    el.className = `status-pill ${ok === true ? "status-healthy" : ok === false ? "status-down" : "status-demo"}`;
}

// Status pills reflect what the server actually measured. Nothing here is hard-coded to "ONLINE".
function updateStatusPills(data) {
    const live = data.data_source === "live";
    const src = document.getElementById("pill-source");
    if (src) {
        src.querySelector(".pill-text").innerText = live ? "DATA: LIVE CLUSTER" : "DATA: DEMO (SIMULATED)";
        src.className = `status-pill ${live ? "status-healthy" : "status-demo"}`;
    }
    const sensors = data.sensors || {};
    const c = sensors.controller, p = sensors.prometheus;
    setPill("pill-controller", "CONTROLLER", c ? c.ok : null, "REACHABLE", c ? "UNREACHABLE" : "N/A (DEMO)");
    setPill("pill-prometheus", "PROMETHEUS", p ? p.ok : null, "REACHABLE", p ? "UNREACHABLE" : "N/A (DEMO)");
}

const fmtPct = (v) => (v === null || v === undefined ? "n/a" : `${v}%`);
const barWidth = (v) => (v === null || v === undefined ? 0 : Math.max(0, Math.min(100, v)));

function handleServerEvent(data) {
    if (data.event === "PIPELINE_EVENT") {
        if (data.latest_terminal_log) {
            appendTerminalLog(data.latest_terminal_log.level, data.latest_terminal_log.category, data.latest_terminal_log.message);
        }
        return;
    }
    if (data.event === "INITIAL_STATE" || data.event === "TELEMETRY_TICK" || data.event === "ESCALATION_RESOLVED") {
        updateStatusPills(data);
        if (data.pods) renderPodCards(data.pods);
        if (data.quarantines) renderQuarantineList(data.quarantines);
        if (data.escalations) renderEscalationsSummary(data.escalations);
        if (data.metrics_summary) updateBannerScorecards(data.metrics_summary);
        if (data.terminal_logs) {
            data.terminal_logs.forEach(log => appendTerminalLog(log.level, log.category, log.message));
        }
    } else if (data.event === "CHAOS_TRIGGERED") {
        if (data.latest_terminal_log) {
            appendTerminalLog(data.latest_terminal_log.level, data.latest_terminal_log.category, data.latest_terminal_log.message);
        }
    }
}

function updateBannerScorecards(summary) {
    document.getElementById("val-health-score").innerText = `${summary.health_score_pct.toFixed(1)}%`;
    document.getElementById("val-active-pods").innerText = summary.active_pods;
    document.getElementById("val-quarantined-pods").innerText = summary.quarantined_pods;
    document.getElementById("val-escalations-count").innerText = summary.escalated_count;
    
    const subEsc = document.getElementById("sub-escalations");
    if (summary.escalated_count > 0) {
        subEsc.innerText = "⚠️ CLICK POD FOR HITL FIX";
        subEsc.style.color = "var(--neon-alert)";
    } else {
        subEsc.innerText = "No Action Needed";
        subEsc.style.color = "var(--color-text-muted)";
    }
}

let lastPods = [];

function renderPodCards(pods) {
    lastPods = pods;
    const container = document.getElementById("pod-cards-list");
    container.innerHTML = "";

    pods.forEach(pod => {
        const card = document.createElement("div");
        card.className = `pod-card ${pod.status.toLowerCase()}`;
        
        let statusBadgeClass = "badge-cyan";
        if (pod.status === "QUARANTINED") statusBadgeClass = "badge-red";
        if (pod.status === "DEGRADED" || pod.status === "FAILED") statusBadgeClass = "badge-purple";

        card.innerHTML = `
            <div class="pod-header">
                <div class="pod-name">${pod.pod_name}${pod.namespace ? ` <small>(${pod.namespace})</small>` : ""}</div>
                <span class="badge ${statusBadgeClass}">${pod.status}</span>
            </div>
            <div class="pod-metrics">
                <div class="metric-bar-group">
                    <div class="bar-label"><span>CPU</span> <strong>${fmtPct(pod.cpu_pct)}</strong></div>
                    <div class="progress-track"><div class="progress-fill" style="width: ${barWidth(pod.cpu_pct)}%"></div></div>
                </div>
                <div class="metric-bar-group">
                    <div class="bar-label"><span>MEM</span> <strong>${fmtPct(pod.mem_pct)}</strong></div>
                    <div class="progress-track"><div class="progress-fill" style="width: ${barWidth(pod.mem_pct)}%"></div></div>
                </div>
                <div class="metric-bar-group">
                    <div class="bar-label"><span>ERR</span> <strong>${fmtPct(pod.error_rate_pct)}</strong></div>
                    <div class="progress-track"><div class="progress-fill" style="width: ${barWidth(pod.error_rate_pct === null || pod.error_rate_pct === undefined ? null : pod.error_rate_pct * 10)}%; background: var(--neon-alert)"></div></div>
                </div>
            </div>
        `;
        container.appendChild(card);
    });

    document.getElementById("pod-count-badge").innerText = `${pods.length} Pods Active`;
}

function renderQuarantineList(quarantines) {
    const container = document.getElementById("quarantine-list");
    container.innerHTML = "";

    if (!quarantines || quarantines.length === 0) {
        container.innerHTML = `<div class="empty-state">No pods currently isolated under eBPF network quarantine.</div>`;
        document.getElementById("quarantine-count-badge").innerText = "0 Isolated";
        return;
    }

    quarantines.forEach(item => {
        const div = document.createElement("div");
        div.className = "quarantine-item";
        div.innerHTML = `
            <div>
                <strong style="color: var(--neon-alert); font-family: var(--font-mono); font-size: 13px;">${item.pod_name}</strong>
                <div style="font-size: 11px; color: var(--color-text-muted); margin-top: 2px;">
                    eBPF Cage Active • ${item.mitre_technique}
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <button class="action-btn action-restart" onclick="openForensicsModal('${item.pod_name}')">
                    🔍 Inspect DFIR
                </button>
                <button class="action-btn action-unquarantine" onclick="openHITLDrawerForPod('${item.pod_name}')">
                    🛠️ HITL Fix
                </button>
            </div>
        `;
        container.appendChild(div);
    });

    document.getElementById("quarantine-count-badge").innerText = `${quarantines.length} Isolated`;
}

function renderEscalationsSummary(escalations) {
    if (escalations && escalations.length > 0) {
        currentActiveEscalation = escalations[0];
    } else {
        currentActiveEscalation = null;
    }
}

function appendTerminalLog(level, category, message) {
    const windowEl = document.getElementById("terminal-window");
    if (!windowEl) return;

    const timeStr = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `terminal-log-line log-${level.toLowerCase()}`;
    line.innerHTML = `
        <span class="log-time">[${timeStr}]</span>
        <span class="log-cat">[${category}]</span>
        <span class="log-msg">${message}</span>
    `;

    windowEl.appendChild(line);
    windowEl.scrollTop = windowEl.scrollHeight;
}

// Chaos Injection Trigger
async function triggerChaos(chaosType) {
    appendTerminalLog("WARN", "USER", `Triggering chaos injection '${chaosType}' from UI...`);
    try {
        const resp = await authFetch("/api/v1/chaos/trigger", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pod_name: "aegis-storefront-prod-1", chaos_type: chaosType })
        });
        const res = await resp.json();
        if (res.decision && !res.decision.approved) {
            // Open HITL drawer if escalation triggered!
            setTimeout(() => {
                openHITLDrawerForPod("aegis-storefront-prod-1", res);
            }, 600);
        }
    } catch (e) {
        console.error("Error triggering chaos:", e);
    }
}

// Forensics Modal Functions
async function openForensicsModal(podName) {
    try {
        const resp = await fetch(`/api/v1/forensics/${podName}`);
        const bodyEl = document.getElementById("forensics-modal-body");
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            bodyEl.innerHTML = `<div><strong>No forensics available:</strong> ${err.detail || `HTTP ${resp.status}`}</div>`;
            document.getElementById("forensics-modal").style.display = "flex";
            return;
        }
        const forensics = await resp.json();
        const source = forensics.demo ? "DEMO SAMPLE (not real evidence)" : (forensics.data_source === "cluster" ? "captured from the cluster" : "no cluster data captured");
        const procs = forensics.process_tree || forensics.simulated_process_tree || [];
        bodyEl.innerHTML = `
            <div><strong>Target Pod:</strong> ${forensics.target_pod} ${forensics.namespace ? `(${forensics.namespace})` : ""}</div>
            <div><strong>Source:</strong> ${source}</div>
            <div><strong>Trigger Reason:</strong> ${forensics.trigger_reason}</div>
            <div><strong>MITRE Technique:</strong> ${forensics.mitre_technique || "n/a"}</div>

            <h4 style="margin-top: 10px;">Process Tree Snapshot:</h4>
            <pre class="code-box">${procs.length ? JSON.stringify(procs, null, 2) : "(none captured)"}</pre>

            <h4 style="margin-top: 10px;">Kubernetes Events:</h4>
            <pre class="code-box">${(forensics.events || []).join("\n") || "(none)"}</pre>

            <h4 style="margin-top: 10px;">Container Logs (tail):</h4>
            <pre class="code-box">${Object.entries(forensics.logs || {}).map(([c, l]) => `# ${c}\n${l.join("\n")}`).join("\n\n") || "(none)"}</pre>

            <h4 style="margin-top: 10px;">Collection Errors:</h4>
            <pre class="code-box">${(forensics.errors || []).join("\n") || "(none)"}</pre>
        `;

        document.getElementById("forensics-modal").style.display = "flex";
    } catch (e) {
        console.error("Failed to load forensics snapshot:", e);
    }
}

function closeForensicsModal() {
    document.getElementById("forensics-modal").style.display = "none";
}

// Human-in-the-Loop (HITL) Drawer Functions
function openHITLDrawerForPod(podName, chaosResult) {
    document.getElementById("hitl-pod-name").innerText = podName;

    if (chaosResult) {
        document.getElementById("hitl-inc-id").innerText = `Incident ID: ${chaosResult.verdict.incident_id || 'INC-ESCALATE'}`;
        document.getElementById("hitl-problem-type").innerText = chaosResult.verdict.problem_type || 'UNKNOWN';
        document.getElementById("hitl-confidence").innerText = `${chaosResult.decision.confidence || 0.45} (LOW/REJECTED)`;
        document.getElementById("hitl-reason").innerText = chaosResult.decision.reason || 'Escalation triggered.';
    }

    document.getElementById("hitl-drawer-overlay").style.display = "block";
    document.getElementById("hitl-drawer").classList.add("open");
}

function closeHITLDrawer() {
    document.getElementById("hitl-drawer-overlay").style.display = "none";
    document.getElementById("hitl-drawer").classList.remove("open");
}

async function executeHITLAction(actionType) {
    const podName = document.getElementById("hitl-pod-name").innerText;
    const notes = document.getElementById("hitl-custom-notes").value;
    const incId = document.getElementById("hitl-inc-id").innerText.replace("Incident ID: ", "");

    appendTerminalLog("WARN", "HITL", `Human operator dispatching action '${actionType}' for '${podName}'...`);

    try {
        // The server needs the pod's namespace (live mode refuses to guess one).
        const known = lastPods.find(p => p.pod_name === podName);
        const resp = await authFetch("/api/v1/escalation/resolve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                incident_id: incId,
                target_pod: podName,
                action: actionType,
                notes: notes,
                namespace: known && known.namespace ? known.namespace : null
            })
        });
        const result = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            // Do not report success or close the drawer: the operator must see that nothing happened.
            appendTerminalLog("ERROR", "HITL", `Action '${actionType}' on '${podName}' FAILED: ${result.detail || "HTTP " + resp.status}`);
            return;
        }
        appendTerminalLog("SUCCESS", "HITL", result.message);
        closeHITLDrawer();
        fetchInitialState();
    } catch (e) {
        console.error("Error dispatching HITL resolution:", e);
    }
}

/* ==========================================================================
   PRODUCTION CHAOS SIMULATION TRIGGER
   ========================================================================== */
async function triggerChaos(chaosType, podName = "aegis-storefront-prod-1") {
    appendTerminalLog("WARN", "CHAOS", `[RED TEAM] Injecting failure scenario '${chaosType}' on target pod '${podName}'...`);

    // Add visual loading indicator on the clicked button
    const btn = document.querySelector(`.chaos-${chaosType.split('_')[0]}`);
    if (btn) {
        btn.classList.add("chaos-active");
        btn.disabled = true;
    }

    try {
        const resp = await authFetch("/api/v1/chaos/trigger", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pod_name: podName,
                chaos_type: chaosType
            })
        });

        if (!resp.ok) {
            throw new Error(`Server returned HTTP ${resp.status}`);
        }

        const data = await resp.json();
        const confPct = data.verdict && data.verdict.confidence ? (data.verdict.confidence * 100).toFixed(0) : "95";
        appendTerminalLog("ALERT", "AI_BRAIN", `Diagnosis: ${data.verdict.problem_type} (${confPct}% confidence) -> Action: ${data.decision.final_action}`);

        // If action was rejected or escalated to human, open HITL drawer automatically
        if (!data.decision.approved || data.decision.state === "STATE_ESCALATE_HUMAN") {
            appendTerminalLog("ERROR", "HITL", `Policy requires human authorization. Opening HITL Command Drawer...`);
            openHITLDrawerForPod(data.pod_name, data);
        } else {
            appendTerminalLog("SUCCESS", "CONTROLLER", `Autonomous remediation '${data.decision.final_action}' executed successfully.`);
        }

        // Refresh telemetry cards and scorecards
        fetchInitialState();

    } catch (err) {
        appendTerminalLog("ERROR", "CHAOS", `Chaos injection failed: ${err.message}`);
        console.error("Chaos trigger failed:", err);
    } finally {
        if (btn) {
            btn.classList.remove("chaos-active");
            btn.disabled = false;
        }
    }
}

/* ==========================================================================
   INCIDENT POST-MORTEM REPORT VIEWER
   ========================================================================== */
async function viewLatestPostMortem() {
    viewPostMortem("latest");
}

async function viewPostMortem(incidentId) {
    try {
        appendTerminalLog("INFO", "SYSTEM", `Compiling autonomous incident post-mortem report for '${incidentId}'...`);
        const resp = await fetch(`/api/v1/incidents/${incidentId}/postmortem`);
        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        const data = await resp.json();
        const contentEl = document.getElementById("postmortem-content");
        if (contentEl) {
            contentEl.textContent = data.markdown;
        }
        const modal = document.getElementById("postmortem-modal");
        if (modal) {
            modal.style.display = "flex";
        }
    } catch (e) {
        appendTerminalLog("ERROR", "SYSTEM", `Failed to generate post-mortem: ${e.message}`);
        console.error("Post-mortem fetch error:", e);
    }
}

function closePostMortemModal() {
    const modal = document.getElementById("postmortem-modal");
    if (modal) {
        modal.style.display = "none";
    }
}

function copyPostMortemMarkdown() {
    const contentEl = document.getElementById("postmortem-content");
    if (contentEl) {
        navigator.clipboard.writeText(contentEl.textContent).then(() => {
            appendTerminalLog("SUCCESS", "SYSTEM", "Post-mortem markdown copied to clipboard.");
        });
    }
}
