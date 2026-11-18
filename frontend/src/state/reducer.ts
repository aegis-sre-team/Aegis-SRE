import type { Pod, Snapshot, TerminalLog } from '../api/types'

export type Connection = 'connecting' | 'live' | 'polling' | 'offline'

export interface Series {
  cpu: number[]
  mem: number[]
}

export interface State {
  snapshot: Snapshot | null
  connection: Connection
  logs: TerminalLog[]
  history: Record<string, Series>
  /** epoch ms of the last telemetry frame; drives the "stale" warning */
  lastTickAt: number | null
  /** bumps when the server says persisted data (incidents, audit) changed */
  dataVersion: number
}

export type Action =
  | { type: 'snapshot'; snap: Partial<Snapshot>; at: number }
  | { type: 'logs'; logs: TerminalLog[] }
  | { type: 'connection'; value: Connection }
  | { type: 'bump' }

export const initialState: State = {
  snapshot: null,
  connection: 'connecting',
  logs: [],
  history: {},
  lastTickAt: null,
  dataVersion: 0,
}

export const HISTORY_LEN = 40

export const podKey = (p: Pick<Pod, 'pod_name' | 'namespace'>): string =>
  p.namespace ? `${p.namespace}/${p.pod_name}` : p.pod_name

function pushPoint(arr: number[] | undefined, v: number | null): number[] {
  const next = arr ? arr.slice(-(HISTORY_LEN - 1)) : []
  if (v !== null && v !== undefined) next.push(v)
  return next
}

export function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'snapshot': {
      const merged = { ...(state.snapshot ?? emptySnapshot), ...stripUndefined(action.snap) } as Snapshot
      const history = { ...state.history }
      if (action.snap.pods) {
        for (const p of action.snap.pods) {
          const k = podKey(p)
          const prev = history[k]
          history[k] = { cpu: pushPoint(prev?.cpu, p.cpu_pct), mem: pushPoint(prev?.mem, p.mem_pct) }
        }
      }
      return { ...state, snapshot: merged, history, lastTickAt: action.at }
    }
    case 'logs':
      return { ...state, logs: action.logs.slice(-100) }
    case 'connection':
      return { ...state, connection: action.value }
    case 'bump':
      return { ...state, dataVersion: state.dataVersion + 1 }
  }
}

const emptySnapshot: Snapshot = { data_source: 'demo', pods: [], quarantines: [], escalations: [], sensors: null }

function stripUndefined<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>
}

export function isStale(state: State, now: number, thresholdMs = 8000): boolean {
  return state.connection !== 'offline' && state.lastTickAt !== null && now - state.lastTickAt > thresholdMs
}
