import { useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ArrowLeft, FileText, Search, Siren } from 'lucide-react'
import { api } from '../api/client'
import type { AuditRow, Incident } from '../api/types'
import { useResource } from '../state/hooks'
import { useAegis } from '../state/AegisProvider'
import { Badge, Empty, OutcomeBadge, PageHead } from '../components/bits'
import { Chain } from '../components/Chain'
import { Dialog } from '../components/Dialog'
import { buildChain, matchAudit, outcomeOf } from '../lib/pipeline'
import { actionLabel, confidenceLabel, fullTime, problemLabel, timeAgo } from '../lib/format'

export function Incidents() {
  const { id } = useParams()
  const nav = useNavigate()
  const { now } = useAegis()
  const inc = useResource(() => api.incidents(), 'incidents')
  const aud = useResource(() => api.audit(), 'audit-for-incidents')
  const [q, setQ] = useState('')

  const rows = useMemo(() => {
    const list = inc.data?.incidents ?? []
    const needle = q.trim().toLowerCase()
    return list.filter((i) => !needle || [i.incident_id, i.target_pod, i.problem_type, i.final_action].join(' ').toLowerCase().includes(needle))
  }, [inc.data, q])

  const audits = aud.data?.audit_logs ?? []
  const selected = id ? (inc.data?.incidents.find((i) => i.incident_id === id) ?? null) : null

  return (
    <>
      <PageHead title="Incidents" sub="Every incident Aegis diagnosed, with how far its pipeline got." />
      {inc.error && <p className="error-text">Could not load incidents: {inc.error}</p>}
      <div className={`master-detail${selected ? ' has-detail' : ''}`}>
        <section className="panel master" aria-label="Incident list">
          <div className="search">
            <Search size={16} aria-hidden="true" />
            <input type="search" placeholder="Filter by pod, type or action" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter incidents" />
          </div>
          {inc.loading && !inc.data ? (
            <p className="muted pad">Loading incidents…</p>
          ) : rows.length === 0 ? (
            <Empty icon={<Siren size={28} />} title={q ? 'No incidents match' : 'No incidents yet'}>
              {q ? 'Try a different filter.' : 'When Aegis diagnoses a failure or an attack, it shows up here with its full decision trail.'}
            </Empty>
          ) : (
            <ul className="list">
              {rows.map((i) => {
                const stages = buildChain(i, matchAudit(i, audits))
                return (
                  <li key={i.incident_id}>
                    <button className={`list-item${selected?.incident_id === i.incident_id ? ' is-active' : ''}`} onClick={() => nav(`/incidents/${encodeURIComponent(i.incident_id)}`)}>
                      <span className="list-top">
                        <span className="mono">{i.target_pod}</span>
                        <OutcomeBadge outcome={outcomeOf(stages, i)} />
                      </span>
                      <span className="list-sub meta">
                        <span>{problemLabel(i.problem_type)}</span>
                        <span className="muted">{actionLabel(i.final_action)}</span>
                      </span>
                      <span className="list-meta small muted meta">
                        <span>{i.incident_id}</span>
                        <span>{timeAgo(i.created_at, now)}</span>
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        <section className="detail" aria-label="Incident detail">
          {selected ? (
            <IncidentDetail incident={selected} audits={audits} onBack={() => nav('/incidents')} />
          ) : (
            <div className="panel detail-empty">
              <Empty title="Select an incident">The chain on the right shows what Aegis saw, what it decided, what the guardrails allowed, and whether the fix held.</Empty>
            </div>
          )}
        </section>
      </div>
    </>
  )
}

function IncidentDetail({ incident, audits, onBack }: { incident: Incident; audits: AuditRow[]; onBack: () => void }) {
  const audit = matchAudit(incident, audits)
  const stages = buildChain(incident, audit)
  const [pm, setPm] = useState<{ md: string } | { error: string } | null>(null)

  const openPostmortem = async () => {
    try {
      const r = await api.postmortem(incident.incident_id)
      setPm({ md: r.markdown })
    } catch (e) {
      setPm({ error: e instanceof Error ? e.message : String(e) })
    }
  }

  return (
    <div className="panel">
      <button className="btn btn-quiet back" onClick={onBack}>
        <ArrowLeft size={16} /> All incidents
      </button>
      <header className="detail-head">
        <div>
          <h2 className="mono">{incident.target_pod}</h2>
          <p className="muted small meta">
            <span>{incident.incident_id}</span>
            <span>detected {fullTime(incident.created_at)}</span>
          </p>
        </div>
        <div className="row gap">
          <OutcomeBadge outcome={outcomeOf(stages, incident)} />
          <button className="btn" onClick={openPostmortem}>
            <FileText size={16} /> Post-mortem
          </button>
        </div>
      </header>

      <Chain stages={stages} />

      <dl className="facts">
        <div>
          <dt>Problem</dt>
          <dd>{problemLabel(incident.problem_type)}</dd>
        </div>
        <div>
          <dt>Severity</dt>
          <dd>{incident.threat_level ?? 'Not rated'}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{confidenceLabel(incident.confidence)} (autonomous actions need 70%)</dd>
        </div>
        <div>
          <dt>Proposed</dt>
          <dd>{actionLabel(incident.recommended_action)}</dd>
        </div>
        <div>
          <dt>After guardrails</dt>
          <dd>{stages[2].state === 'blocked' ? 'Nothing approved, sent to a human' : actionLabel(incident.final_action)}</dd>
        </div>
        {incident.mitre_technique && (
          <div>
            <dt>MITRE ATT&CK</dt>
            <dd>
              <Badge tone="defend" dot={false}>
                {incident.mitre_technique}
              </Badge>
            </dd>
          </div>
        )}
      </dl>

      {incident.root_cause && (
        <div className="callout">
          <h3>Root cause</h3>
          <p>{incident.root_cause}</p>
        </div>
      )}
      <p className="small muted">The execution record is matched to this incident by pod and time, because the audit table has no incident id.</p>

      {pm && (
        <Dialog title="Post-mortem" onClose={() => setPm(null)} width={820}>
          {'md' in pm ? (
            <div className="markdown">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{pm.md}</ReactMarkdown>
            </div>
          ) : (
            <p className="error-text">{pm.error}</p>
          )}
        </Dialog>
      )}
    </div>
  )
}
