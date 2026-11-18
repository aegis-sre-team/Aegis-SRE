import type { ReactNode } from 'react'
import type { Outcome } from '../lib/pipeline'
import { OUTCOME_LABEL } from '../lib/pipeline'

export type Tone = 'ok' | 'warn' | 'bad' | 'defend' | 'info' | 'neutral'

export function Badge({ tone = 'neutral', children, dot = true }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  return (
    <span className={`badge tone-${tone}`}>
      {dot && <i aria-hidden="true" />}
      {children}
    </span>
  )
}

const STATUS_TONE: Record<string, Tone> = {
  HEALTHY: 'ok',
  DEGRADED: 'warn',
  QUARANTINED: 'defend',
  FAILED: 'bad',
  COMPLETED: 'neutral',
}
const STATUS_LABEL: Record<string, string> = {
  HEALTHY: 'Healthy',
  DEGRADED: 'Degraded',
  QUARANTINED: 'Quarantined',
  FAILED: 'Failed',
  COMPLETED: 'Completed',
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={STATUS_TONE[status] ?? 'neutral'}>{STATUS_LABEL[status] ?? status}</Badge>
}

const OUTCOME_TONE: Record<Outcome, Tone> = {
  resolved: 'ok',
  contained: 'defend',
  'needs-human': 'warn',
  failed: 'bad',
  'dry-run': 'info',
  open: 'neutral',
}

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  return <Badge tone={OUTCOME_TONE[outcome]}>{OUTCOME_LABEL[outcome]}</Badge>
}

/** A horizontal meter. value === null renders an explicit "no data" state, never an empty 0% bar. */
export function Meter({ label, value, warnAt = 75, badAt = 90 }: { label: string; value: number | null; warnAt?: number; badAt?: number }) {
  const known = value !== null && value !== undefined && !Number.isNaN(value)
  const v = known ? Math.max(0, Math.min(100, value as number)) : 0
  const tone = !known ? 'none' : v >= badAt ? 'bad' : v >= warnAt ? 'warn' : 'ok'
  return (
    <div className="meter" role="img" aria-label={known ? `${label} ${v.toFixed(0)} percent` : `${label}: no data`}>
      <span className="meter-label">{label}</span>
      <span className={`meter-track meter-${tone}`}>
        <span style={{ width: `${v}%` }} />
      </span>
      <span className="meter-value">{known ? `${v.toFixed(0)}%` : 'no data'}</span>
    </div>
  )
}

export function Sparkline({ values, tone = 'info' }: { values: number[]; tone?: 'info' | 'warn' }) {
  if (values.length < 2) return <svg className="spark" viewBox="0 0 100 24" aria-hidden="true" />
  const w = 100
  const h = 24
  const step = w / (values.length - 1)
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (Math.max(0, Math.min(100, v)) / 100) * (h - 4)).toFixed(1)}`)
  return (
    <svg className={`spark spark-${tone}`} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true">
      <polyline points={pts.join(' ')} fill="none" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      {icon}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  )
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p className="muted">{sub}</p>}
      </div>
      {actions && <div className="row gap">{actions}</div>}
    </header>
  )
}

export function Banner({ tone = 'warn', title, children, action }: { tone?: Tone; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className={`banner tone-${tone}`} role={tone === 'bad' ? 'alert' : 'status'}>
      <div>
        <strong>{title}</strong>
        {children && <p>{children}</p>}
      </div>
      {action}
    </div>
  )
}
