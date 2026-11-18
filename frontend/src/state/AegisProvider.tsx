import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { ServerEvent, Snapshot } from '../api/types'
import { initialState, reducer, isStale, type State } from './reducer'

interface Ctx {
  state: State
  stale: boolean
  now: number
  refreshState: () => Promise<void>
}

const AegisContext = createContext<Ctx | null>(null)

export function useAegis(): Ctx {
  const c = useContext(AegisContext)
  if (!c) throw new Error('useAegis must be used inside <AegisProvider>')
  return c
}

const POLL_MS = 3000

export function AegisProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState)
  const [now, setNow] = useState(() => Date.now())
  const pollRef = useRef<number | null>(null)

  const refreshState = useCallback(async () => {
    try {
      const t = await api.state()
      const { terminal_logs, ...snap } = t
      dispatch({ type: 'snapshot', snap: snap as Snapshot, at: Date.now() })
      dispatch({ type: 'logs', logs: terminal_logs ?? [] })
    } catch {
      /* the connection indicator already reflects an unreachable server */
    }
  }, [])

  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [])

  useEffect(() => {
    let ws: WebSocket | null = null
    let retry: number | null = null
    let attempts = 0
    let closed = false

    const stopPolling = () => {
      if (pollRef.current !== null) {
        window.clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
    const startPolling = () => {
      if (pollRef.current !== null) return
      pollRef.current = window.setInterval(async () => {
        try {
          const t = await api.state()
          const { terminal_logs, ...snap } = t
          dispatch({ type: 'snapshot', snap: snap as Snapshot, at: Date.now() })
          dispatch({ type: 'logs', logs: terminal_logs ?? [] })
          dispatch({ type: 'connection', value: 'polling' })
        } catch {
          dispatch({ type: 'connection', value: 'offline' })
        }
      }, POLL_MS)
    }

    const connect = () => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      ws = new WebSocket(`${proto}//${window.location.host}/ws/telemetry`)
      ws.onopen = () => {
        attempts = 0
        stopPolling()
        dispatch({ type: 'connection', value: 'live' })
      }
      ws.onmessage = (msg) => {
        let ev: ServerEvent
        try {
          ev = JSON.parse(msg.data as string) as ServerEvent
        } catch {
          return
        }
        const at = Date.now()
        switch (ev.event) {
          case 'INITIAL_STATE':
          case 'TELEMETRY_TICK': {
            const { event: _e, terminal_logs, ...snap } = ev
            void _e
            dispatch({ type: 'snapshot', snap, at })
            if (ev.event === 'INITIAL_STATE' && terminal_logs) dispatch({ type: 'logs', logs: terminal_logs })
            break
          }
          case 'ESCALATION_RESOLVED': {
            const { event: _e, ...snap } = ev
            void _e
            dispatch({ type: 'snapshot', snap, at })
            dispatch({ type: 'bump' })
            void refreshState()
            break
          }
          default:
            // PIPELINE_EVENT, CHAOS_TRIGGERED: persisted data changed and the server log has new lines.
            dispatch({ type: 'bump' })
            void refreshState()
        }
      }
      ws.onclose = () => {
        if (closed) return
        dispatch({ type: 'connection', value: 'polling' })
        startPolling()
        attempts += 1
        retry = window.setTimeout(connect, Math.min(15000, 1000 * 2 ** attempts))
      }
      ws.onerror = () => ws?.close()
    }

    void refreshState()
    connect()
    return () => {
      closed = true
      if (retry !== null) window.clearTimeout(retry)
      stopPolling()
      ws?.close()
    }
  }, [refreshState])

  const stale = isStale(state, now)
  const value = useMemo(() => ({ state, stale, now, refreshState }), [state, stale, now, refreshState])
  return <AegisContext.Provider value={value}>{children}</AegisContext.Provider>
}
