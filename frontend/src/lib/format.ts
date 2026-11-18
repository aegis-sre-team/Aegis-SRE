export const pct = (v: number | null | undefined, digits = 0): string =>
  v === null || v === undefined || Number.isNaN(v) ? 'no data' : `${v.toFixed(digits)}%`

export const confidenceLabel = (c: number | null | undefined): string =>
  c === null || c === undefined ? 'unknown' : `${Math.round(c * 100)}%`

/** "RESTART_POD" -> "Restart pod" */
export const humanize = (s: string | null | undefined): string => {
  if (!s) return 'none'
  const t = s.replace(/_/g, ' ').toLowerCase()
  return t.charAt(0).toUpperCase() + t.slice(1)
}

export const ACTION_LABEL: Record<string, string> = {
  RESTART_POD: 'Restart workload',
  SCALE_DEPLOYMENT: 'Scale up by one',
  CILIUM_QUARANTINE_EBPF: 'Quarantine pod',
  UNQUARANTINE_POD: 'Release quarantine',
  ESCALATE: 'Escalate to a human',
}

export const actionLabel = (a: string | null | undefined): string => (a ? (ACTION_LABEL[a] ?? humanize(a)) : 'No action')

export const PROBLEM_LABEL: Record<string, string> = {
  OPERATIONAL_BUG: 'Operational failure',
  RESOURCE_CAPACITY: 'Resource capacity',
  SECURITY_ATTACK: 'Security attack',
  SENSOR_DARK: 'Sensor dark',
  HUMAN_OPERATOR: 'Operator action',
}

export const problemLabel = (p: string | null | undefined): string => (p ? (PROBLEM_LABEL[p] ?? humanize(p)) : 'Unclassified')

/** Parses "2026-05-01T10:00:00Z" style stamps; returns null for "HH:MM:SS" or junk. */
export function parseStamp(s: string | number | null | undefined): Date | null {
  if (s === null || s === undefined || s === '') return null
  const d = typeof s === 'number' ? new Date(s * 1000) : new Date(s)
  return Number.isNaN(d.getTime()) ? null : d
}

export function timeAgo(s: string | number | null | undefined, now: number = Date.now()): string {
  const d = parseStamp(s)
  if (!d) return typeof s === 'string' ? s : ''
  const sec = Math.max(0, Math.round((now - d.getTime()) / 1000))
  if (sec < 60) return `${sec}s ago`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`
  return `${Math.floor(sec / 86400)}d ago`
}

export function clockTime(s: string | number | null | undefined): string {
  const d = parseStamp(s)
  if (!d) return typeof s === 'string' ? s : ''
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function fullTime(s: string | number | null | undefined): string {
  const d = parseStamp(s)
  return d ? d.toLocaleString() : typeof s === 'string' ? s : ''
}
