import { Fragment, useMemo, useState } from 'react'
import { ChevronRight, ScrollText, Search } from 'lucide-react'
import { api } from '../api/client'
import { useResource } from '../state/hooks'
import { Badge, Empty, PageHead } from '../components/bits'
import { actionLabel, fullTime, problemLabel } from '../lib/format'
import { resultOf } from '../lib/pipeline'
import type { AuditRow } from '../api/types'

type Result = 'all' | 'ok' | 'failed'

function ResultBadge({ row }: { row: AuditRow }) {
  switch (resultOf(row)) {
    case 'ok':
      return <Badge tone="ok">Succeeded</Badge>
    case 'dry-run':
      return <Badge tone="info">Dry run</Badge>
    case 'escalated':
      return <Badge tone="warn">Escalated</Badge>
    default:
      return <Badge tone="bad">Failed</Badge>
  }
}

export function Audit() {
  const r = useResource(() => api.audit(), 'audit-page', 15000)
  const [q, setQ] = useState('')
  const [result, setResult] = useState<Result>('all')
  const [action, setAction] = useState('all')
  const [open, setOpen] = useState<number | null>(null)

  const rows = r.data?.audit_logs ?? []
  const actions = useMemo(() => Array.from(new Set(rows.map((x) => x.executed_action))).sort(), [rows])
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rows.filter(
      (x) =>
        (result === 'all' || (result === 'ok' ? ['ok', 'dry-run'].includes(resultOf(x)) : ['failed', 'escalated'].includes(resultOf(x)))) &&
        (action === 'all' || x.executed_action === action) &&
        (!needle || [x.target_pod, x.problem_type, x.executed_action, x.details, x.status_code].join(' ').toLowerCase().includes(needle)),
    )
  }, [rows, q, result, action])

  return (
    <>
      <PageHead title="Audit log" sub="Every action the executor ran or refused, newest first. Showing the latest 50." />
      <section className="panel">
        <div className="toolbar">
          <div className="search grow">
            <Search size={16} aria-hidden="true" />
            <input type="search" placeholder="Filter by pod, action or detail" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter audit log" />
          </div>
          <label className="select">
            <span className="sr-only">Result</span>
            <select value={result} onChange={(e) => setResult(e.target.value as Result)}>
              <option value="all">All results</option>
              <option value="ok">Succeeded</option>
              <option value="failed">Failed or escalated</option>
            </select>
          </label>
          <label className="select">
            <span className="sr-only">Action</span>
            <select value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="all">All actions</option>
              {actions.map((a) => (
                <option key={a} value={a}>
                  {actionLabel(a)}
                </option>
              ))}
            </select>
          </label>
        </div>

        {r.error && <p className="error-text pad">Could not load the audit log: {r.error}</p>}
        {r.loading && !r.data ? (
          <p className="muted pad">Loading…</p>
        ) : shown.length === 0 ? (
          <Empty icon={<ScrollText size={28} />} title={rows.length ? 'No entries match' : 'No actions recorded yet'}>
            {rows.length ? 'Clear a filter to see more.' : 'Each action Aegis takes or refuses is written here.'}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table-audit">
              <thead>
                <tr>
                  <th aria-label="Expand" />
                  <th>Time</th>
                  <th>Pod</th>
                  <th>Action</th>
                  <th>Result</th>
                  <th>Verified</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((x) => (
                  <Fragment key={x.id}>
                    <tr className={open === x.id ? 'is-open' : ''}>
                      <td>
                        <button className="icon-btn" aria-expanded={open === x.id} aria-label={`Details for entry ${x.id}`} onClick={() => setOpen(open === x.id ? null : x.id)}>
                          <ChevronRight size={16} className={open === x.id ? 'rot' : ''} />
                        </button>
                      </td>
                      <td className="nowrap">{fullTime(x.timestamp)}</td>
                      <td className="mono">{x.target_pod}</td>
                      <td>{actionLabel(x.executed_action)}</td>
                      <td>
                        <ResultBadge row={x} />
                      </td>
                      <td>
                        {resultOf(x) === 'ok' && x.health_verified === true ? (
                          <Badge tone="ok">Healthy</Badge>
                        ) : resultOf(x) === 'ok' && x.health_verified === false ? (
                          <Badge tone="bad">Unhealthy</Badge>
                        ) : (
                          <span className="muted">{resultOf(x) === 'ok' ? 'Not checked' : 'None'}</span>
                        )}
                      </td>
                    </tr>
                    {open === x.id && (
                      <tr className="row-detail">
                        <td />
                        <td colSpan={5}>
                          <dl className="facts">
                            <div>
                              <dt>Problem</dt>
                              <dd>{problemLabel(x.problem_type)}</dd>
                            </div>
                            <div>
                              <dt>Status code</dt>
                              <dd className="mono">{x.status_code}</dd>
                            </div>
                            <div className="wide">
                              <dt>Details</dt>
                              <dd>{x.details || 'None recorded'}</dd>
                            </div>
                            {x.forensics_file && (
                              <div className="wide">
                                <dt>Forensics file</dt>
                                <dd className="mono">{x.forensics_file}</dd>
                              </div>
                            )}
                          </dl>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
