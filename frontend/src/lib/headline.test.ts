import { describe, expect, it } from 'vitest'
import type { PodStatus } from '../api/types'
import { statusHeadline, summarizePods } from './headline'

const pods = (...statuses: PodStatus[]) => statuses.map((status) => ({ status }))
const base = { hasReading: true, pods: pods('HEALTHY', 'HEALTHY'), sensorsDown: [] as string[], waiting: 0, quarantines: 0 }

describe('summarizePods', () => {
  it('counts completed Job pods in the total but never as a problem', () => {
    expect(summarizePods(pods('HEALTHY', 'COMPLETED', 'DEGRADED', 'FAILED', 'QUARANTINED'))).toEqual({
      total: 5,
      healthy: 1,
      attention: 2,
      failed: 1,
      quarantined: 1,
    })
  })

  it('treats an unrecognised status as needing attention, never as healthy', () => {
    expect(summarizePods([{ status: 'MYSTERY' as PodStatus }]).attention).toBe(1)
  })
})

describe('statusHeadline', () => {
  it('does not claim anything before the first reading', () => {
    const h = statusHeadline({ ...base, hasReading: false, pods: [] })
    expect(h.tone).toBe('neutral')
    expect(h.title).toMatch(/waiting/i)
  })

  it('says healthy only when a reading exists, sensors answered and nothing waits on a person', () => {
    const h = statusHeadline(base)
    expect(h.tone).toBe('ok')
    expect(h.title).toBe('Everything is healthy.')
  })

  it('never says healthy while a sensor is down', () => {
    const h = statusHeadline({ ...base, sensorsDown: ['prometheus'] })
    expect(h.tone).toBe('bad')
    expect(h.title).not.toMatch(/healthy/i)
    expect(h.detail).toMatch(/no data/)
  })

  it('puts a pending human decision first, with correct plurals', () => {
    expect(statusHeadline({ ...base, waiting: 1, sensorsDown: ['loki'] }).title).toBe('1 incident needs a decision.')
    expect(statusHeadline({ ...base, waiting: 3 }).title).toBe('3 incidents need a decision.')
    expect(statusHeadline({ ...base, waiting: 3 }).tone).toBe('warn')
  })

  it('goes red only when a pod has failed outright', () => {
    expect(statusHeadline({ ...base, pods: pods('HEALTHY', 'DEGRADED') }).tone).toBe('warn')
    const failed = statusHeadline({ ...base, pods: pods('HEALTHY', 'FAILED', 'DEGRADED') })
    expect(failed.tone).toBe('bad')
    expect(failed.title).toBe('2 pods need attention.')
    expect(failed.detail).toBe('1 of 3 pods are running and ready.')
  })

  it('reports contained pods as defended rather than healthy', () => {
    const h = statusHeadline({ ...base, pods: pods('HEALTHY', 'QUARANTINED') })
    expect(h.tone).toBe('defend')
    expect(h.title).toBe('1 pod is quarantined.')
  })

  it('does not call the cluster healthy while a quarantine is active, even if pod rows lag behind', () => {
    const h = statusHeadline({ ...base, quarantines: 1 })
    expect(h.tone).toBe('defend')
    expect(h.title).toBe('1 pod is quarantined.')
  })

  it('says so when there are no pods', () => {
    expect(statusHeadline({ ...base, pods: [] }).title).toBe('No pods found.')
  })
})
