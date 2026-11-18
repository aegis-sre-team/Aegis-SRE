// Shapes of the payloads served by src/dashboard/server.py.

export type DataSource = 'live' | 'demo'

export type PodStatus = 'HEALTHY' | 'DEGRADED' | 'QUARANTINED' | 'FAILED' | 'COMPLETED' | string

export interface Pod {
  pod_name: string
  namespace?: string
  app?: string | null
  node?: string | null
  ip?: string | null
  status: PodStatus
  restart_count: number
  /** null means "no data": Prometheus had no series. It is never shown as 0. */
  cpu_pct: number | null
  mem_pct: number | null
  error_rate_pct?: number | null
  last_updated?: string
}

export interface Sensor {
  ok: boolean
  detail: string
}

export interface Quarantine {
  pod_name: string
  mitre_technique: string
  forensics_file: string
  quarantined_at: string | number
}

export interface Escalation {
  incident_id: string
  target_pod: string
  problem_type: string | null
  confidence: number | null
  reason: string
  mitre_technique?: string | null
  forensics_file?: string
  loki_logs?: string
  timestamp: string
}

export interface TerminalLog {
  timestamp: string
  level: 'INFO' | 'WARN' | 'ALERT' | 'ERROR' | 'SUCCESS' | string
  category: string
  message: string
}

export interface Snapshot {
  data_source: DataSource
  pods: Pod[]
  quarantines: Quarantine[]
  escalations: Escalation[]
  sensors: Record<string, Sensor> | null
  error?: string | null
}

export interface Incident {
  id: number
  incident_id: string
  target_pod: string
  problem_type: string
  threat_level: string | null
  mitre_technique: string | null
  root_cause: string | null
  recommended_action: string | null
  final_action: string | null
  confidence: number | null
  guardrail_approved: boolean | null
  guardrail_reason: string | null
  status: string | null
  created_at: string | null
}

export interface AuditRow {
  id: number
  timestamp: string
  target_pod: string
  problem_type: string | null
  executed_action: string
  execution_success: boolean
  status_code: string
  details: string | null
  forensics_file: string | null
  health_verified: boolean | null
}

export interface Forensics {
  demo?: boolean
  timestamp?: string
  target_pod?: string
  namespace?: string
  mitre_technique?: string
  trigger_reason?: string
  process_tree?: unknown[]
  simulated_process_tree?: unknown[]
  active_sockets?: unknown[]
  events?: unknown[]
  logs?: Record<string, unknown>
  errors?: string[]
}

export interface ExecutionResult {
  success?: boolean
  dry_run?: boolean
  status_code?: string
  details?: string
  health_verified?: boolean | null
  executed_action?: string
}

export interface ChaosResult {
  event: 'CHAOS_TRIGGERED'
  pod_name: string
  chaos_type: string
  verdict: {
    problem_type?: string
    recommended_action?: string
    confidence?: number
    root_cause?: string
    mitre_technique?: string | null
    _ai_provider?: string
    [k: string]: unknown
  }
  decision: { approved: boolean; final_action: string; state: string; reason: string }
  execution: ExecutionResult
}

export type ServerEvent =
  | ({ event: 'INITIAL_STATE' | 'TELEMETRY_TICK'; terminal_logs?: TerminalLog[] } & Snapshot)
  | { event: 'PIPELINE_EVENT'; [k: string]: unknown }
  | { event: 'CHAOS_TRIGGERED'; [k: string]: unknown }
  | ({ event: 'ESCALATION_RESOLVED' } & Partial<Snapshot>)
