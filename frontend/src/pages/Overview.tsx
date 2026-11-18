import { Link } from 'react-router-dom'
import { useMemo } from 'react'
import { ArrowRight, Boxes } from 'lucide-react'
import { useAegis } from '../state/AegisProvider'
import { podKey } from '../state/reducer'
import { api } from '../api/client'
import { useResource } from '../state/hooks'
import { Banner, Empty, Meter, PageHead, Sparkline, StatusBadge } from '../components/bits'
import { actionLabel, clockTime, timeAgo } from '../lib/format'
import { resultOf } from '../lib/pipeline'
import type { Pod, TerminalLog } from '../api/types'

const LEVEL_TONE: Record<string, string> = { SUCCESS: 'ok', ERROR: 'bad', ALERT: 'bad', WARN: 'warn', INFO: 'neutral' }
const RESULT_WORD = { ok: 'succeeded', failed: 'failed', escalated: 'escalated to a human', 'dry-run': 'ran as a dry run' } as const

export function Overview() {
  const { state, now } = useAegis()
  const snap = state.snapshot
  const audit = useResource(() => api.audit(), 'overview-audit')

  const pods = snap?.pods ?? []
  const counts = useMemo(() => {
    const c = { healthy: 0, degraded: 0, quarantined: 0 }
    for (const p of pods) {
      if (p.status === 'HEALTHY') c.healthy++
      else if (p.status === 'QUARANTINED') c.quarantined++
      else c.degraded++
    }
    return c
  }, [pods])

  const sensorsDown = snap?.sensors ? Object.entries(snap.sensors).filter(([, s]) => !s.ok) : []
  const lastAction = audit.data?.audit_logs[0]
  const waiting = snap?.escalations.length ?? 0
  const demo = snap?.data_source !== 'live'

  return (
    <>
      <PageHead
        title="Overview"
        sub={
          demo
            ? 'Simulated pods. Nothing here reflects a real cluster, and the Simulate page can inject failures.'
            : 'Pods in the managed namespaces, read from the controller and Prometheus.'
        }
      />

      {sensorsDown.length > 0 && (
        <Banner tone="bad" title={`${sensorsDown.map(([n]) => n).join(' and ')} not reachable`}>
          {sensorsDown.map(([n, s]) => `${n}: ${s.detail}`).join('. ')}. Missing data shows as “no data”, and Aegis escalates to a human instead of guessing.
        </Banner>
      )}
      {snap?.error && !sensorsDown.length && (
        <Banner tone="warn" title="Cluster read failed">
          {snap.error}
        </Banner>
      )}
      {waiting > 0 && (
        <Banner
          tone="warn"
          title={`${waiting} ${waiting === 1 ? 'incident needs' : 'incidents need'} a decision`}
          action={
            <Link className="btn btn-primary" to="/review">
              Review <ArrowRight size={16} />
            </Link>
          }
        >
          Aegis stopped before acting. Nothing runs on these until a person decides.
        </Banner>
      )}

      <section className="kpis" aria-label="Summary">
        <div className="kpi">
          <span className="kpi-label">Healthy pods</span>
          <span className="kpi-value">
            {counts.healthy}
            <small> of {pods.length}</small>
          </span>
          <span className="kpi-note">{counts.degraded > 0 ? `${counts.degraded} degraded or failing` : 'None degraded'}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Quarantined</span>
          <span className="kpi-value">{snap?.quarantines.length ?? 0}</span>
          <span className="kpi-note">{(snap?.quarantines.length ?? 0) > 0 ? 'Alive for forensics, network cut' : 'No pods isolated'}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Waiting for a human</span>
          <span className="kpi-value">{waiting}</span>
          <span className="kpi-note">{waiting > 0 ? 'Open the review queue' : 'Queue is clear'}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Last action</span>
          <span className="kpi-value kpi-text">{lastAction ? actionLabel(lastAction.executed_action) : 'None yet'}</span>
          <span className="kpi-note">
            {lastAction ? `${lastAction.target_pod}, ${RESULT_WORD[resultOf(lastAction)]} ${timeAgo(lastAction.timestamp, now)}` : 'No actions recorded'}
          </span>
        </div>
      </section>

      <div className="split">
        <section className="panel" aria-labelledby="pods-h">
          <header className="panel-head">
            <h2 id="pods-h">Pods</h2>
            <span className="muted">{pods.length} total</span>
          </header>
          {pods.length === 0 ? (
            <Empty icon={<Boxes size={28} />} title={snap ? 'No pods found' : 'Waiting for the first reading'}>
              {snap
                ? 'The controller returned no pods for the managed namespaces. Check DASHBOARD_NAMESPACES and the controller logs.'
                : 'The dashboard has not received telemetry yet.'}
            </Empty>
          ) : (
            <ul className="pod-list">
              {pods.map((p) => (
                <PodRow key={podKey(p)} pod={p} cpu={state.history[podKey(p)]?.cpu ?? []} mem={state.history[podKey(p)]?.mem ?? []} />
              ))}
            </ul>
          )}
        </section>

        <section className="panel" aria-labelledby="feed-h">
          <header className="panel-head">
            <h2 id="feed-h">Activity</h2>
            <span className="muted">Latest first</span>
          </header>
          <Feed logs={state.logs} />
        </section>
      </div>
    </>
  )
}

function PodRow({ pod, cpu, mem }: { pod: Pod; cpu: number[]; mem: number[] }) {
  return (
    <li className="pod-row">
      <div className="pod-id">
        <span className="mono pod-name">{pod.pod_name}</span>
        <span className="muted small">
          {[pod.namespace, pod.app, pod.node].filter(Boolean).join(' · ') || 'Simulated pod'}
        </span>
      </div>
      <StatusBadge status={pod.status} />
      <div className="pod-meters">
        <Meter label="CPU" value={pod.cpu_pct} />
        <Meter label="Memory" value={pod.mem_pct} />
      </div>
      <div className="pod-spark" aria-hidden="true">
        <Sparkline values={cpu} />
        <Sparkline values={mem} tone="warn" />
      </div>
      <span className="pod-restarts small muted" title="Restarts since the pod was created">
        {pod.restart_count} {pod.restart_count === 1 ? 'restart' : 'restarts'}
      </span>
    </li>
  )
}

function Feed({ logs }: { logs: TerminalLog[] }) {
  if (logs.length === 0) return <Empty title="No activity yet">Events from the brain, guardrails and controller appear here as they happen.</Empty>
  return (
    <ol className="feed">
      {[...logs].reverse().map((l, i) => (
        <li key={`${l.timestamp}-${i}`} className={`feed-row lvl-${LEVEL_TONE[l.level] ?? 'neutral'}`}>
          <time className="mono small muted">{clockTime(l.timestamp)}</time>
          <span className="feed-cat small">{l.category.replace(/_/g, ' ').toLowerCase()}</span>
          <span className="feed-msg">{l.message}</span>
        </li>
      ))}
    </ol>
  )
}
