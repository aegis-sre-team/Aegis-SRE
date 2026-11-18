import { api, ApiError } from '../api/client'
import type { Forensics as ForensicsData } from '../api/types'
import { useResource } from '../state/hooks'
import { Badge } from './bits'
import { fullTime } from '../lib/format'

const asText = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v))

const NO_CLUSTER = 'DRY_RUN_NO_CLUSTER_DATA'

function Table({ rows, cols }: { rows: unknown[]; cols: { key: string; label: string }[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {cols.map((c) => (
                <td key={c.key} className="mono">
                  {asText((r as Record<string, unknown>)[c.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Section({ title, children, count }: { title: string; children: React.ReactNode; count?: number }) {
  return (
    <section className="f-section">
      <h3>
        {title}
        {count !== undefined && <span className="muted"> ({count})</span>}
      </h3>
      {children}
    </section>
  )
}

export function ForensicsView({ pod }: { pod: string }) {
  const r = useResource<ForensicsData>(() => api.forensics(pod), `forensics-${pod}`, 60000)

  if (r.loading && !r.data) return <p className="muted">Loading forensics…</p>
  if (r.error) {
    const missing = r.error.toLowerCase().includes('no forensics')
    return (
      <div className="callout">
        <h3>{missing ? 'Nothing was captured' : 'Could not load forensics'}</h3>
        <p>{r.error}</p>
        {missing && <p className="muted small">A snapshot exists only after a quarantine ran against a real cluster. Aegis does not invent one.</p>}
      </div>
    )
  }
  const f = r.data
  if (!f) return null

  const tree = (f.process_tree ?? f.simulated_process_tree ?? []) as unknown[]
  const dryRun = tree.some((t) => asText(t).includes(NO_CLUSTER))
  const sockets = f.active_sockets ?? []
  const events = f.events ?? []
  const logs = f.logs ?? {}

  return (
    <div className="forensics">
      {f.demo && (
        <p className="notice">
          <Badge tone="warn">Demo sample</Badge> This is a fixed example, not a capture from a real pod.
        </p>
      )}
      {dryRun && (
        <p className="notice">
          <Badge tone="warn">Dry run</Badge> The controller ran in dry-run mode, so no process data was collected.
        </p>
      )}
      {!dryRun && !f.demo && tree.length === 0 && sockets.length === 0 && events.length === 0 && (
        <p className="notice">
          <Badge tone="warn">Empty capture</Badge> The snapshot holds no processes, sockets or events. The collector may have had nothing to read, or the run was simulated.
        </p>
      )}
      <dl className="facts">
        <div>
          <dt>Captured</dt>
          <dd>{fullTime(f.timestamp) || 'Unknown'}</dd>
        </div>
        <div>
          <dt>Namespace</dt>
          <dd>{f.namespace ?? 'Unknown'}</dd>
        </div>
        <div>
          <dt>Technique</dt>
          <dd>{f.mitre_technique ?? 'Not mapped'}</dd>
        </div>
        <div className="wide">
          <dt>Trigger</dt>
          <dd>{f.trigger_reason ?? 'Not recorded'}</dd>
        </div>
      </dl>

      {!dryRun && (
        <Section title="Processes" count={tree.length}>
          {tree.length === 0 ? (
            <p className="muted">No processes recorded.</p>
          ) : (
            <Table rows={tree} cols={[{ key: 'pid', label: 'PID' }, { key: 'user', label: 'User' }, { key: 'cmd', label: 'Command' }]} />
          )}
        </Section>
      )}
      <Section title="Open sockets" count={sockets.length}>
        {sockets.length === 0 ? <p className="muted">No sockets recorded.</p> : <pre className="code">{sockets.map(asText).join('\n')}</pre>}
      </Section>
      <Section title="Runtime events" count={events.length}>
        {events.length === 0 ? <p className="muted">No runtime events recorded.</p> : <pre className="code">{events.map(asText).join('\n')}</pre>}
      </Section>
      {Object.keys(logs).length > 0 && (
        <Section title="Logs">
          <pre className="code">{Object.entries(logs).map(([k, v]) => `# ${k}\n${asText(v)}`).join('\n\n')}</pre>
        </Section>
      )}
      {(f.errors?.length ?? 0) > 0 && (
        <Section title="Capture warnings">
          <ul className="plain">
            {f.errors!.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  )
}

export { ApiError }
