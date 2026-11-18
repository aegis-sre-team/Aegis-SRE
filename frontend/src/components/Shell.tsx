import { NavLink, Outlet } from 'react-router-dom'
import { Activity, FlaskConical, Monitor, Moon, ScrollText, ShieldAlert, Siren, Sun, UserCheck, WifiOff } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useAegis } from '../state/AegisProvider'
import { Badge } from './bits'

type Theme = 'system' | 'light' | 'dark'

function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = localStorage.getItem('aegis-theme')
      return t === 'light' || t === 'dark' ? t : 'system'
    } catch {
      return 'system'
    }
  })
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'system') delete root.dataset.theme
    else root.dataset.theme = theme
    try {
      if (theme === 'system') localStorage.removeItem('aegis-theme')
      else localStorage.setItem('aegis-theme', theme)
    } catch {
      /* ignore */
    }
  }, [theme])
  return [theme, setTheme]
}

export function Shell() {
  const { state, stale } = useAegis()
  const [theme, setTheme] = useTheme()
  const snap = state.snapshot
  const demo = snap?.data_source !== 'live'
  const needsHuman = snap?.escalations.length ?? 0
  const caged = snap?.quarantines.length ?? 0

  const next: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' }
  const ThemeIcon = theme === 'system' ? Monitor : theme === 'light' ? Sun : Moon

  return (
    <div className="shell">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <aside className="rail">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 3 5 7v8c0 7 4.7 12.3 11 14 6.3-1.7 11-7 11-14V7z" fill="var(--brand)" />
            <path d="m11 16 4 4 7-8" fill="none" stroke="var(--brand-ink)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
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
          {demo && (
            <NavLink to="/simulate">
              <FlaskConical size={18} />
              <span>Simulate</span>
            </NavLink>
          )}
        </nav>
        <div className="rail-foot">
          <button className="btn btn-quiet" onClick={() => setTheme(next[theme])} aria-label={`Theme: ${theme}. Switch theme`}>
            <ThemeIcon size={16} />
            <span>{theme === 'system' ? 'Match system' : theme === 'light' ? 'Light' : 'Dark'}</span>
          </button>
        </div>
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
