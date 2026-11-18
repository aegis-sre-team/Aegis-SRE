import { Check, Minus, ShieldAlert, X, HelpCircle } from 'lucide-react'
import type { Stage, StageState } from '../lib/pipeline'

const STATE_WORD: Record<StageState, string> = {
  passed: 'passed',
  blocked: 'blocked',
  failed: 'failed',
  skipped: 'did not run',
  unknown: 'not recorded',
}

function Glyph({ state }: { state: StageState }) {
  const p = { size: 16, strokeWidth: 2.5, 'aria-hidden': true as const }
  switch (state) {
    case 'passed':
      return <Check {...p} />
    case 'blocked':
      return <ShieldAlert {...p} />
    case 'failed':
      return <X {...p} />
    case 'skipped':
      return <Minus {...p} />
    default:
      return <HelpCircle {...p} />
  }
}

/**
 * The incident chain: detected -> diagnosed -> guardrails -> acted -> verified. Each station shows how
 * far the autonomous pipeline got and exactly where it stopped, so an operator can judge the decision.
 */
export function Chain({ stages, compact = false }: { stages: Stage[]; compact?: boolean }) {
  return (
    <ol className={`chain${compact ? ' chain-compact' : ''}`} aria-label="Incident pipeline">
      {stages.map((s, i) => {
        const next = stages[i + 1]
        // The line leaving a station is solid only if this station passed and the next one ran.
        const linkLive = s.state === 'passed' && !!next && next.state !== 'skipped'
        return (
          <li key={s.key} className={`stage stage-${s.state}${linkLive ? ' link-live' : ''}`}>
            <span className="stage-node" title={`${s.title} ${STATE_WORD[s.state]}`}>
              <Glyph state={s.state} />
            </span>
            <div className="stage-text">
              <span className="stage-title">
                {s.title}
                <span className="sr-only"> {STATE_WORD[s.state]}</span>
              </span>
              <span className="stage-summary">{s.summary}</span>
              {!compact && s.detail && <span className="stage-detail">{s.detail}</span>}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
