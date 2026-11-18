import { describe, expect, it } from 'vitest'
import type { Pod } from '../api/types'
import { HISTORY_LEN, initialState, isStale, podKey, reducer } from './reducer'

const pod = (over: Partial<Pod> = {}): Pod => ({
  pod_name: 'web-1',
  namespace: 'shop',
  status: 'HEALTHY',
  restart_count: 0,
  cpu_pct: 20,
  mem_pct: 40,
  ...over,
})

describe('reducer', () => {
  it('records history per namespaced pod and caps its length', () => {
    let s = initialState
    for (let i = 0; i < HISTORY_LEN + 10; i++) {
      s = reducer(s, { type: 'snapshot', snap: { pods: [pod({ cpu_pct: i })] }, at: i })
    }
    expect(s.history[podKey(pod())].cpu).toHaveLength(HISTORY_LEN)
    expect(s.history[podKey(pod())].cpu.at(-1)).toBe(HISTORY_LEN + 9)
  })

  it('never turns missing metrics into zero', () => {
    const s = reducer(initialState, { type: 'snapshot', snap: { pods: [pod({ cpu_pct: null, mem_pct: null })] }, at: 1 })
    expect(s.history['shop/web-1'].cpu).toEqual([])
    expect(s.history['shop/web-1'].mem).toEqual([])
  })

  it('merges a partial update without dropping data_source or sensors', () => {
    let s = reducer(initialState, {
      type: 'snapshot',
      snap: { data_source: 'live', pods: [pod()], sensors: { controller: { ok: true, detail: 'ok' } } },
      at: 1,
    })
    s = reducer(s, { type: 'snapshot', snap: { escalations: [], pods: undefined }, at: 2 })
    expect(s.snapshot?.data_source).toBe('live')
    expect(s.snapshot?.sensors?.controller.ok).toBe(true)
    expect(s.snapshot?.pods).toHaveLength(1)
  })

  it('flags a stale feed only while a connection exists', () => {
    const s = reducer(initialState, { type: 'snapshot', snap: { pods: [] }, at: 1000 })
    expect(isStale({ ...s, connection: 'live' }, 20000)).toBe(true)
    expect(isStale({ ...s, connection: 'live' }, 3000)).toBe(false)
    expect(isStale({ ...s, connection: 'offline' }, 20000)).toBe(false)
  })
})
