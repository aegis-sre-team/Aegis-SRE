import { NavLink, Outlet } from 'react-router-dom'
import { Activity, FlaskConical, ScrollText, ShieldAlert, Siren, UserCheck, WifiOff } from 'lucide-react'
import { simulateNavLabel } from '../lib/chaos'
import { useAegis } from '../state/AegisProvider'
import { Badge } from './bits'

export function Shell() {
  const { state, stale } = useAegis()
  const snap = state.snapshot
  const demo = snap?.data_source !== 'live'
  const needsHuman = snap?.escalations.length ?? 0
  const caged = snap?.quarantines.length ?? 0

  return (
    <div className="shell">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <aside className="rail">
        <div className="brand">
          <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 3 5 7v8c0 7 4.7 12.3 11 14 6.3-1.7 11-7 11-14V7z" fill="var(--cobalt)" />
            <path d="m11 16 4 4 7-8" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span>Aegis</span>
        </div>
        <nav aria-label="Primary">
          <NavLink to="/" end>
            <Activity size={18} />
            <span>Overview</span>
          </NavLink>
          <NavLink to="/incidents">
            <Siren size={18} />
            <span>Incidents</span>
          </NavLink>
          <NavLink to="/review">
            <UserCheck size={18} />
            <span>Needs a human</span>
            {needsHuman > 0 && <b className="count count-warn">{needsHuman}</b>}
          </NavLink>
          <NavLink to="/quarantine">
            <ShieldAlert size={18} />
            <span>Quarantine</span>
            {caged > 0 && <b className="count count-defend">{caged}</b>}
          </NavLink>
          <NavLink to="/audit">
            <ScrollText size={18} />
            <span>Audit log</span>
          </NavLink>
          <NavLink to="/simulate">
            <FlaskConical size={18} />
            <span>{simulateNavLabel(!demo)}</span>
          </NavLink>
        </nav>
      </aside>

      <div className="stage-area">
        <div className="statusbar" role="status">
          {snap === null ? (
            <Badge tone="neutral">Connecting</Badge>
          ) : demo ? (
            <Badge tone="warn">Simulated demo data</Badge>
          ) : (
            <Badge tone="ok">Live cluster</Badge>
          )}
          {snap?.sensors &&
            Object.entries(snap.sensors).map(([name, s]) => (
              <span key={name} title={s.detail} className="sensor">
                <Badge tone={s.ok ? 'ok' : 'bad'}>
                  {name.charAt(0).toUpperCase() + name.slice(1)} {s.ok ? 'up' : 'down'}
                </Badge>
              </span>
            ))}
          <span className="spacer" />
          {state.connection === 'offline' ? (
            <span className="conn conn-bad">
              <WifiOff size={14} /> Server unreachable
            </span>
          ) : state.connection === 'polling' ? (
            <span className="conn conn-warn">Reconnecting, polling every 3s</span>
          ) : stale ? (
            <span className="conn conn-warn">Feed is stale</span>
          ) : state.connection === 'live' ? (
            <span className="conn conn-ok">Streaming</span>
          ) : (
            <span className="conn">Connecting</span>
          )}
        </div>
        <main id="main" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
