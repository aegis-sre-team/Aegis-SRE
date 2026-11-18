import { useState } from 'react'
import { Link } from 'react-router-dom'
import { FlaskConical } from 'lucide-react'
import { api } from '../api/client'
import type { ChaosResult, Incident } from '../api/types'
import { useAegis } from '../state/AegisProvider'
import { useFeedback } from '../state/feedback'
import { Banner, Empty, PageHead } from '../components/bits'
import { Chain } from '../components/Chain'
import { buildChain } from '../lib/pipeline'

const SCENARIOS = [
  { id: 'oom', title: 'Memory runs out', note: 'Memory climbs to 94%. Expect a restart.' },
  { id: 'http500', title: 'Error spike', note: 'About 18% of requests fail. Expect a restart.' },
  { id: 'cpu', title: 'CPU saturation', note: 'CPU pins at 98%. Expect a scale-up.' },
  { id: 't1059_shell', title: 'Shell inside a container', note: 'A reverse shell spawns. Expect a quarantine.' },
  { id: 't1552_credentials', title: 'Credential file read', note: 'A secret is read from disk. Expect a quarantine.' },
]

/** Turns the simulator response into the same chain the Incidents page draws. */
function toChain(r: ChaosResult) {
  const v = r.verdict
  const inc: Incident = {
    id: 0,
    incident_id: 'simulation',
    target_pod: r.pod_name,
    problem_type: v.problem_type ?? 'UNKNOWN',
    threat_level: null,
    mitre_technique: v.mitre_technique ?? null,
    root_cause: typeof v.root_cause === 'string' ? v.root_cause : null,
    recommended_action: v.recommended_action ?? null,
    final_action: r.decision.final_action,
    confidence: typeof v.confidence === 'number' ? v.confidence : null,
    guardrail_approved: r.decision.approved,
    guardrail_reason: r.decision.reason,
    status: null,
    created_at: null,
  }
  const ex = r.execution
  const audit = r.decision.approved
    ? {
        id: 0,
        timestamp: '',
        target_pod: r.pod_name,
        problem_type: inc.problem_type,
        executed_action: r.decision.final_action,
        execution_success: ex.success !== false,
        status_code: ex.status_code ?? '',
        details: ex.details ?? null,
        forensics_file: null,
        health_verified: ex.health_verified ?? null,
      }
    : null
  return buildChain(inc, audit)
}

export function Simulate() {
  const { state } = useAegis()
  const { toast, withAuth } = useFeedback()
  const snap = state.snapshot
  const pods = snap?.pods ?? []
  const [pod, setPod] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [last, setLast] = useState<ChaosResult | null>(null)

  if (snap?.data_source === 'live') {
    return (
      <>
        <PageHead title="Simulate" />
        <Banner tone="info" title="Simulation is only available with demo data">
          Against a live cluster, inject failures with kubectl. The steps are in k8s/PHASE6_VERIFY.md.
        </Banner>
      </>
    )
  }

  const target = pod || pods[0]?.pod_name || ''

  const run = async (id: string) => {
    setBusy(id)
    try {
      const res = await withAuth(() => api.chaos({ pod_name: target, chaos_type: id }))
      setLast(res)
    } catch (e) {
      toast('error', e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <PageHead title="Simulate" sub="Inject a failure into a simulated pod and watch Aegis diagnose it, check the guardrails and act." />
      <Banner tone="warn" title="Demo data only">
        These pods and metrics are simulated. The diagnosis and guardrails are real code, but no cluster is touched.
      </Banner>

      <section className="panel">
        <header className="panel-head">
          <h2>Scenario</h2>
          <label className="select">
            <span className="sr-only">Target pod</span>
            <select value={target} onChange={(e) => setPod(e.target.value)}>
              {pods.map((p) => (
                <option key={p.pod_name} value={p.pod_name}>
                  {p.pod_name}
                </option>
              ))}
            </select>
          </label>
        </header>
        <div className="scenarios">
          {SCENARIOS.map((s) => (
            <button key={s.id} className="scenario" disabled={busy !== null || !target} onClick={() => void run(s.id)}>
              <span className="scenario-title">{s.title}</span>
              <span className="muted small">{busy === s.id ? 'Diagnosing…' : s.note}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="panel" aria-live="polite">
        <header className="panel-head">
          <h2>Result</h2>
          {last && (
            <span className="muted small">
              {last.pod_name} · diagnosed by {String(last.verdict._ai_provider ?? 'unknown provider')}
            </span>
          )}
        </header>
        {last ? (
          <>
            <Chain stages={toChain(last)} />
            <p className="muted small">
              The full record is on the <Link to="/incidents">Incidents</Link> and <Link to="/audit">Audit log</Link> pages.
            </p>
          </>
        ) : (
          <Empty icon={<FlaskConical size={28} />} title="No run yet">
            Pick a scenario above. The chain appears here once Aegis has diagnosed it.
          </Empty>
        )}
      </section>
    </>
  )
}
