import type { AuditRow, ChaosResult, ChaosScenario, ExecutionResult, Forensics, Incident, Snapshot, TerminalLog } from './types'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

const TOKEN_KEY = 'aegis-token'

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable: the token lives only for this call chain */
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['X-Aegis-Token'] = token
  const res = await fetch(path, { ...init, headers: { ...headers, ...(init.headers as Record<string, string>) } })
  if (!res.ok) {
    let detail = res.statusText || `HTTP ${res.status}`
    try {
      const body = await res.json()
      const d = body?.detail ?? body
      detail = typeof d === 'string' ? d : JSON.stringify(d)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail)
  }
  return (await res.json()) as T
}

export interface Telemetry extends Snapshot {
  terminal_logs: TerminalLog[]
}

export const api = {
  state: () => request<Telemetry>('/api/v1/telemetry/state'),
  incidents: () => request<{ count: number; incidents: Incident[]; error?: string }>('/api/v1/db/incidents'),
  audit: () => request<{ count: number; audit_logs: AuditRow[]; error?: string }>('/api/v1/db/audit'),
  forensics: (pod: string) => request<Forensics>(`/api/v1/forensics/${encodeURIComponent(pod)}`),
  postmortem: (incidentId: string) =>
    request<{ markdown: string }>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/postmortem`),
  resolve: (body: { incident_id: string; target_pod: string; action: string; notes: string; namespace?: string }) =>
    request<{ status: string; message: string; execution: ExecutionResult | null }>('/api/v1/escalation/resolve', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  chaos: (body: { pod_name: string; chaos_type: string }) =>
    request<ChaosResult>('/api/v1/chaos/trigger', { method: 'POST', body: JSON.stringify(body) }),
  // Live chaos scenarios (the controller starts and stops them; the dashboard relays).
  chaosScenarios: () => request<{ scenarios: ChaosScenario[] }>('/api/v1/chaos/scenarios'),
  chaosStart: (id: string, ttlMinutes?: number) =>
    request<ChaosScenario>(`/api/v1/chaos/scenarios/${encodeURIComponent(id)}/start`, {
      method: 'POST',
      body: JSON.stringify(ttlMinutes ? { ttl_minutes: ttlMinutes } : {}),
    }),
  chaosStop: (id: string) =>
    request<ChaosScenario>(`/api/v1/chaos/scenarios/${encodeURIComponent(id)}/stop`, { method: 'POST' }),
  chaosStopAll: () => request<{ stopped: string[] }>('/api/v1/chaos/stop-all', { method: 'POST' }),
}
