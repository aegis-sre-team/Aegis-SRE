import type { ChaosScenario } from '../api/types'

export type ScenarioState = 'not-installed' | 'stopped' | 'starting' | 'running'
export type ScenarioKind = 'operational' | 'security' | 'human'

export interface ScenarioInfo {
  title: string
  /** Plain words: what it does, then what Aegis should do about it. */
  note: string
  kind: ScenarioKind
}

/** Display order. Must list exactly the scenarios the controller allows (controller/chaos.go). */
export const SCENARIO_ORDER = [
  'cpu-spike',
  'oom',
  'crashloop',
  'http-500',
  'shell-injection',
  'credential-read',
  'network-recon',
  'restart-storm',
]

export const SCENARIO_INFO: Record<string, ScenarioInfo> = {
  'cpu-spike': { title: 'CPU saturation', note: 'Pins CPU above 70% of its limit. Aegis should scale it up.', kind: 'operational' },
  oom: {
    title: 'Memory runs out',
    note: 'Allocates past its memory limit and gets killed. Aegis should restart it, but no alert can see a dead container yet (needs kube-state-metrics), so no incident is raised.',
    kind: 'operational',
  },
  crashloop: {
    title: 'Crash loop',
    note: 'Exits as soon as it starts, again and again. Aegis should restart it, but no alert can see crash loops yet (needs kube-state-metrics), so no incident is raised.',
    kind: 'operational',
  },
  'http-500': {
    title: 'Request flood',
    note: 'Sends a steady stream of requests, including bad ones, to the shop frontend. No alert rule watches HTTP errors yet, so this may raise no incident.',
    kind: 'operational',
  },
  'shell-injection': { title: 'Shell in a container', note: 'A shell is spawned inside the pod (MITRE T1059). Aegis should quarantine it.', kind: 'security' },
  'credential-read': { title: 'Credential file read', note: 'Reads /etc/shadow (MITRE T1552). Aegis should quarantine it.', kind: 'security' },
  'network-recon': { title: 'Network scan tool', note: 'Runs nc against the cluster API address (MITRE T1046). Aegis should quarantine it.', kind: 'security' },
  'restart-storm': {
    title: 'Restart storm',
    note: 'Starts fine, then fails after 20 seconds, every time. Restarts do not help, so after 3 restarts in an hour it should escalate to a human. Not detected yet: it needs the crash-loop alert, which needs kube-state-metrics.',
    kind: 'human',
  },
}

export function scenarioState(s: ChaosScenario): ScenarioState {
  if (!s.installed) return 'not-installed'
  if (s.replicas <= 0) return 'stopped'
  return s.ready > 0 ? 'running' : 'starting'
}

/** "12 min left", "under 1 min left", or null when there is no usable future time. */
export function timeLeft(expiresAt: string | undefined, now: number): string | null {
  if (!expiresAt) return null
  const end = Date.parse(expiresAt)
  if (Number.isNaN(end) || end <= now) return null
  const minutes = Math.floor((end - now) / 60_000)
  return minutes < 1 ? 'under 1 min left' : `${minutes} min left`
}
