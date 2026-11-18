import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ShieldCheck, Unlock } from 'lucide-react'
import { api } from '../api/client'
import { useAegis } from '../state/AegisProvider'
import { useFeedback } from '../state/feedback'
import { Badge, Empty, PageHead } from '../components/bits'
import { Dialog } from '../components/Dialog'
import { ForensicsView } from '../components/Forensics'
import { timeAgo } from '../lib/format'

export function Quarantine() {
  const { pod: selectedPod } = useParams()
  const nav = useNavigate()
  const { state, now, refreshState } = useAegis()
  const { toast, withAuth } = useFeedback()
  const snap = state.snapshot
  const list = snap?.quarantines ?? []
  const selected = selectedPod ? (list.find((q) => q.pod_name === selectedPod) ?? null) : null
  const live = snap?.data_source === 'live'

  const [confirm, setConfirm] = useState(false)
  const [namespace, setNamespace] = useState('')
  const [busy, setBusy] = useState(false)

  const podInfo = selected ? snap?.pods.find((p) => p.pod_name === selected.pod_name) : undefined
  const ns = namespace || podInfo?.namespace || ''
  const nsOk = !live || /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(ns)

  const release = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const res = await withAuth(() =>
        api.resolve({
          incident_id: `QUARANTINE-${selected.pod_name}`,
          target_pod: selected.pod_name,
          action: 'UNQUARANTINE_POD',
          notes: 'Released from the Aegis console after forensic review',
          namespace: ns || undefined,
        }),
      )
      toast('ok', res.execution?.dry_run ? 'Release ran as a dry run. Nothing changed in the cluster.' : `${selected.pod_name} released.`)
      setConfirm(false)
      await refreshState()
      nav('/quarantine')
    } catch (e) {
      toast('error', e instanceof Error ? e.message : String(e))
      setConfirm(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHead title="Quarantine" sub="Compromised pods are cut off from the network but kept running, so their state can be examined." />
      <div className={`master-detail${selected ? ' has-detail' : ''}`}>
        <section className="panel master" aria-label="Quarantined pods">
          {list.length === 0 ? (
            <Empty icon={<ShieldCheck size={28} />} title="No pods in quarantine">
              When Aegis detects an attack, the pod is isolated with a Cilium policy and listed here with its forensic snapshot.
            </Empty>
          ) : (
            <ul className="list">
              {list.map((q) => (
                <li key={q.pod_name}>
                  <button className={`list-item is-caged${selected?.pod_name === q.pod_name ? ' is-active' : ''}`} onClick={() => nav(`/quarantine/${encodeURIComponent(q.pod_name)}`)}>
                    <span className="list-top">
                      <span className="mono">{q.pod_name}</span>
                      <Badge tone="defend">Isolated</Badge>
                    </span>
                    <span className="list-sub">{q.mitre_technique}</span>
                    <span className="list-meta small muted">Since {typeof q.quarantined_at === 'string' && q.quarantined_at.length <= 8 ? q.quarantined_at : timeAgo(q.quarantined_at, now)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="detail" aria-label="Forensics">
          {selected ? (
            <div className="panel">
              <button className="btn btn-quiet back" onClick={() => nav('/quarantine')}>
                <ArrowLeft size={16} /> All quarantined pods
              </button>
              <header className="detail-head">
                <div>
                  <h2 className="mono">{selected.pod_name}</h2>
                  <p className="muted small">{selected.mitre_technique}</p>
                </div>
                <button className="btn" onClick={() => setConfirm(true)}>
                  <Unlock size={16} /> Release
                </button>
              </header>
              <ForensicsView pod={selected.pod_name} />
              {confirm && (
                <Dialog title="Release this pod?" onClose={() => !busy && setConfirm(false)} width={460}>
                  <p>
                    <strong className="mono">{selected.pod_name}</strong> gets its network back. Release it only after you have finished reviewing the forensics. Aegis never does this on its own.
                  </p>
                  {live && !podInfo?.namespace && (
                    <label className="field">
                      <span>Namespace</span>
                      <input value={namespace} onChange={(e) => setNamespace(e.target.value.trim())} placeholder="online-boutique" spellCheck={false} />
                    </label>
                  )}
                  <div className="row end gap">
                    <button className="btn" onClick={() => setConfirm(false)} disabled={busy}>
                      Cancel
                    </button>
                    <button className="btn btn-primary" onClick={() => void release()} disabled={busy || !nsOk}>
                      {busy ? 'Working…' : 'Release pod'}
                    </button>
                  </div>
                </Dialog>
              )}
            </div>
          ) : (
            <div className="panel detail-empty">
              <Empty title="Select a pod">You will see the process tree, sockets and runtime events captured at the moment of isolation.</Empty>
            </div>
          )}
        </section>
      </div>
    </>
  )
}
