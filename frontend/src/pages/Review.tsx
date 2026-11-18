import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, CircleCheck } from 'lucide-react'
import { api } from '../api/client'
import type { Escalation } from '../api/types'
import { useAegis } from '../state/AegisProvider'
import { useFeedback } from '../state/feedback'
import { Badge, Empty, PageHead, StatusBadge } from '../components/bits'
import { Dialog } from '../components/Dialog'
import { ForensicsView } from '../components/Forensics'
import { confidenceLabel, problemLabel, timeAgo } from '../lib/format'

interface Option {
  action: 'RESTART_POD' | 'SCALE_DEPLOYMENT' | 'UNQUARANTINE_POD' | 'CUSTOM'
  title: string
  effect: string
  button: string
}

const OPTIONS: Option[] = [
  { action: 'RESTART_POD', title: 'Restart the workload', effect: 'Rolls the owning Deployment so its pods are replaced.', button: 'Restart workload' },
  { action: 'SCALE_DEPLOYMENT', title: 'Scale up by one', effect: 'Adds one replica, up to the controller’s MAX_REPLICAS cap.', button: 'Scale up' },
  { action: 'UNQUARANTINE_POD', title: 'Release the quarantine', effect: 'Removes the network cage. The pod can talk again.', button: 'Release pod' },
  { action: 'CUSTOM', title: 'Mark as handled', effect: 'Closes this item without touching the cluster.', button: 'Mark handled' },
]

export function Review() {
  const { id } = useParams()
  const nav = useNavigate()
  const { state, now } = useAegis()
  const list = state.snapshot?.escalations ?? []
  const selected = id ? (list.find((e) => e.incident_id === id) ?? null) : null

  return (
    <>
      <PageHead title="Needs a human" sub="Aegis stopped before acting on these. Nothing runs until you choose." />
      <div className={`master-detail${selected ? ' has-detail' : ''}`}>
        <section className="panel master" aria-label="Review queue">
          {list.length === 0 ? (
            <Empty icon={<CircleCheck size={28} />} title="Queue is clear">
              Items appear here when confidence is below 70%, a guardrail blocks an action, a fix fails verification, or a sensor goes dark.
            </Empty>
          ) : (
            <ul className="list">
              {list.map((e) => (
                <li key={e.incident_id}>
                  <button className={`list-item${selected?.incident_id === e.incident_id ? ' is-active' : ''}`} onClick={() => nav(`/review/${encodeURIComponent(e.incident_id)}`)}>
                    <span className="list-top">
                      <span className="mono">{e.target_pod}</span>
                      <Badge tone="warn">{confidenceLabel(e.confidence)}</Badge>
                    </span>
                    <span className="list-sub">{e.reason}</span>
                    <span className="list-meta small muted">
                      {problemLabel(e.problem_type)} · {timeAgo(e.timestamp, now)}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="detail" aria-label="Decision">
          {selected ? (
            <Decision key={selected.incident_id} item={selected} onBack={() => nav('/review')} onDone={() => nav('/review')} />
          ) : (
            <div className="panel detail-empty">
              <Empty title="Select an item">You will see Aegis’s reasoning, the evidence it had, and the actions you can take.</Empty>
            </div>
          )}
        </section>
      </div>
    </>
  )
}

function Decision({ item, onBack, onDone }: { item: Escalation; onBack: () => void; onDone: () => void }) {
  const { state, refreshState } = useAegis()
  const { toast, withAuth } = useFeedback()
  const snap = state.snapshot
  const live = snap?.data_source === 'live'
  const pod = snap?.pods.find((p) => p.pod_name === item.target_pod)
  const caged = snap?.quarantines.some((q) => q.pod_name === item.target_pod) ?? false

  const [choice, setChoice] = useState<Option['action'] | null>(null)
  const [namespace, setNamespace] = useState(pod?.namespace ?? '')
  const [notes, setNotes] = useState('')
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)

  const option = OPTIONS.find((o) => o.action === choice) ?? null
  const needsNamespace = live && choice !== null && choice !== 'CUSTOM'
  const nsOk = !needsNamespace || /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(namespace)

  const run = async () => {
    if (!option) return
    setBusy(true)
    try {
      const res = await withAuth(() =>
        api.resolve({
          incident_id: item.incident_id,
          target_pod: item.target_pod,
          action: option.action,
          notes: notes.trim() || 'Manual operator resolution from the Aegis console',
          namespace: namespace || undefined,
        }),
      )
      const dry = res.execution?.dry_run
      toast('ok', dry ? `${option.button} ran as a dry run. Nothing changed in the cluster.` : `${option.button} done for ${item.target_pod}.`)
      setConfirming(false)
      await refreshState()
      onDone()
    } catch (e) {
      toast('error', e instanceof Error ? e.message : String(e))
      setConfirming(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <button className="btn btn-quiet back" onClick={onBack}>
        <ArrowLeft size={16} /> Back to queue
      </button>
      <header className="detail-head">
        <div>
          <h2 className="mono">{item.target_pod}</h2>
          <p className="muted small">
            {item.incident_id} · {item.timestamp}
          </p>
        </div>
        <Badge tone="warn">{confidenceLabel(item.confidence)} confidence</Badge>
      </header>

      <div className="callout">
        <h3>Why Aegis stopped</h3>
        <p>{item.reason}</p>
      </div>

      <dl className="facts">
        <div>
          <dt>Problem</dt>
          <dd>{problemLabel(item.problem_type)}</dd>
        </div>
        <div>
          <dt>Pod state</dt>
          <dd>{caged ? <StatusBadge status="QUARANTINED" /> : pod ? <StatusBadge status={pod.status} /> : 'Not in the pod list'}</dd>
        </div>
        {item.mitre_technique && (
          <div>
            <dt>MITRE ATT&CK</dt>
            <dd>{item.mitre_technique}</dd>
          </div>
        )}
      </dl>

      {item.loki_logs && (
        <section className="f-section">
          <h3>Log evidence{live ? '' : ' (simulated sample)'}</h3>
          <pre className="code">{item.loki_logs}</pre>
        </section>
      )}
      {caged && (
        <section className="f-section">
          <h3>Forensics</h3>
          <ForensicsView pod={item.target_pod} />
        </section>
      )}

      <section className="f-section" aria-labelledby="choose">
        <h3 id="choose">Your decision</h3>
        <div className="options" role="radiogroup" aria-labelledby="choose">
          {OPTIONS.filter((o) => o.action !== 'UNQUARANTINE_POD' || caged).map((o) => (
            <label key={o.action} className={`option${choice === o.action ? ' is-on' : ''}`}>
              <input type="radio" name="decision" checked={choice === o.action} onChange={() => setChoice(o.action)} />
              <span className="option-title">{o.title}</span>
              <span className="option-effect">{o.effect}</span>
            </label>
          ))}
        </div>

        {choice && (
          <div className="decision-form">
            {needsNamespace && (
              <label className="field">
                <span>Namespace</span>
                <input value={namespace} onChange={(e) => setNamespace(e.target.value.trim())} placeholder="online-boutique" spellCheck={false} />
                <small className={nsOk ? 'muted' : 'error-text'}>{nsOk ? 'Required against a live cluster. Protected namespaces are refused.' : 'Use a valid Kubernetes namespace name.'}</small>
              </label>
            )}
            <label className="field">
              <span>Note for the audit trail</span>
              <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Why you chose this" />
            </label>
            <div className="row end">
              <button className="btn btn-primary" disabled={!nsOk || busy} onClick={() => (option?.action === 'CUSTOM' ? void run() : setConfirming(true))}>
                {option?.button}
              </button>
            </div>
          </div>
        )}
      </section>

      {confirming && option && (
        <Dialog title={`${option.button}?`} onClose={() => !busy && setConfirming(false)} width={460}>
          <p>
            <strong className="mono">{item.target_pod}</strong>
            {namespace && <span className="muted"> in {namespace}</span>}
          </p>
          <p>{option.effect}</p>
          <p className="muted small">This runs through the same executor and audit log as autonomous actions.</p>
          <div className="row end gap">
            <button className="btn" onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </button>
            <button className="btn btn-primary" onClick={() => void run()} disabled={busy}>
              {busy ? 'Working…' : option.button}
            </button>
          </div>
        </Dialog>
      )}
    </div>
  )
}
