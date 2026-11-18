import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Play, Square } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { ChaosScenario } from '../api/types'
import { SCENARIO_INFO, SCENARIO_ORDER, scenarioState, timeLeft, type ScenarioKind, type ScenarioState } from '../lib/chaos'
import { useAegis } from '../state/AegisProvider'
import { useFeedback } from '../state/feedback'
import { Badge, Banner, Empty, type Tone } from './bits'

const KIND_TONE: Record<ScenarioKind, Tone> = { operational: 'info', security: 'defend', human: 'warn' }
const KIND_LABEL: Record<ScenarioKind, string> = { operational: 'Operational', security: 'Security', human: 'Needs a human' }
const STATE_TONE: Record<ScenarioState, Tone> = { 'not-installed': 'neutral', stopped: 'neutral', starting: 'info', running: 'warn' }
const STATE_LABEL: Record<ScenarioState, string> = {
  'not-installed': 'Not installed',
  stopped: 'Stopped',
  starting: 'Starting',
  running: 'Running',
}
const POLL_MS = 5000

const message = (e: unknown) => (e instanceof ApiError || e instanceof Error ? e.message : String(e))

export function ChaosControls() {
  const { state, now } = useAegis()
  const { toast, withAuth } = useFeedback()
  const [scenarios, setScenarios] = useState<ChaosScenario[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const res = await api.chaosScenarios()
      setScenarios(res.scenarios)
      setError(null)
    } catch (e) {
      setError(message(e))
    }
  }, [])

  // Reload on mount, whenever the server says something changed, and every few seconds (pods take a moment to become ready).
  useEffect(() => {
    void load()
    const t = window.setInterval(() => void load(), POLL_MS)
    return () => window.clearInterval(t)
  }, [load, state.dataVersion])

  const act = async (key: string, run: () => Promise<unknown>, done: string) => {
    setBusy(key)
    try {
      await withAuth(run)
      toast('ok', done)
      await load()
    } catch (e) {
      toast('error', message(e))
    } finally {
      setBusy(null)
    }
  }

  const byId = new Map((scenarios ?? []).map((s) => [s.id, s]))
  const ordered = SCENARIO_ORDER.map((id) => byId.get(id)).filter((s): s is ChaosScenario => s !== undefined)
  const anyRunning = ordered.some((s) => scenarioState(s) === 'running' || scenarioState(s) === 'starting')

  return (
    <>
      {error && (
        <Banner tone="bad" title="Cannot reach the chaos controls">
          {error}
        </Banner>
      )}

      <section className="panel">
        <header className="panel-head">
          <h2>Scenarios</h2>
          <button
            className="btn"
            disabled={busy !== null || !anyRunning}
            onClick={() => void act('*', () => api.chaosStopAll(), 'Everything is stopped.')}
          >
            <Square size={14} /> Stop all
          </button>
        </header>

        {scenarios === null && !error ? (
          <p className="muted small">Loading scenarios…</p>
        ) : ordered.length === 0 ? (
          <Empty title="No scenarios found">The controller did not report any chaos scenarios.</Empty>
        ) : (
          <div className="scenarios">
            {ordered.map((s) => {
              const info = SCENARIO_INFO[s.id]
              const st = scenarioState(s)
              const left = timeLeft(s.expires_at, now)
              const on = st === 'running' || st === 'starting'
              return (
                <article key={s.id} className={`scenario-card${on ? ' is-on' : ''}`}>
                  <div className="scenario-card-top">
                    <span className="scenario-title">{info.title}</span>
                    <Badge tone={KIND_TONE[info.kind]} dot={false}>
                      {KIND_LABEL[info.kind]}
                    </Badge>
                  </div>
                  <p className="muted small">{info.note}</p>
                  <div className="scenario-card-foot">
                    <span className="meta small">
                      <Badge tone={STATE_TONE[st]}>{STATE_LABEL[st]}</Badge>
                      {on && left && <span className="muted">{left}</span>}
                    </span>
                    {st === 'not-installed' ? (
                      <span className="muted small mono">apply k8s/chaos/{s.deployment}.yaml</span>
                    ) : on ? (
                      <button className="btn" disabled={busy !== null} onClick={() => void act(s.id, () => api.chaosStop(s.id), `${info.title} stopped.`)}>
                        <Square size={14} /> Stop
                      </button>
                    ) : (
                      <button
                        className="btn btn-primary"
                        disabled={busy !== null}
                        onClick={() => void act(s.id, () => api.chaosStart(s.id), `${info.title} started. Watch the Incidents page.`)}
                      >
                        <Play size={14} /> {busy === s.id ? 'Starting…' : 'Start'}
                      </button>
                    )}
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      <p className="muted small">
        Incidents show up on <Link to="/incidents">Incidents</Link> and the audit trail on <Link to="/audit">Audit log</Link>. Anything that needs a
        decision appears under <Link to="/review">Needs a human</Link>.
      </p>
    </>
  )
}
