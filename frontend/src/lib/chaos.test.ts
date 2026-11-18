import { describe, expect, it } from 'vitest'
import type { ChaosScenario } from '../api/types'
import { SCENARIO_INFO, SCENARIO_ORDER, scenarioState, timeLeft } from './chaos'

const base: ChaosScenario = { id: 'cpu-spike', deployment: 'chaos-cpu-spike', installed: true, replicas: 0, ready: 0 }

describe('scenarioState', () => {
  it('reports a scenario whose manifest is not applied as not installed, even with stale numbers', () => {
    expect(scenarioState({ ...base, installed: false, replicas: 1, ready: 1 })).toBe('not-installed')
  })
  it('reports zero replicas as stopped', () => {
    expect(scenarioState(base)).toBe('stopped')
  })
  it('reports a started but not yet ready pod as starting', () => {
    expect(scenarioState({ ...base, replicas: 1, ready: 0 })).toBe('starting')
  })
  it('reports a ready pod as running', () => {
    expect(scenarioState({ ...base, replicas: 1, ready: 1 })).toBe('running')
  })
})

describe('timeLeft', () => {
  const now = Date.parse('2026-11-18T12:00:00Z')
  const at = (ms: number) => new Date(now + ms).toISOString()

  it('says whole minutes left', () => {
    expect(timeLeft(at(12 * 60_000), now)).toBe('12 min left')
    expect(timeLeft(at(12 * 60_000 + 20_000), now)).toBe('12 min left')
    expect(timeLeft(at(90_000), now)).toBe('1 min left')
  })
  it('says under a minute instead of 0 min', () => {
    expect(timeLeft(at(59_000), now)).toBe('under 1 min left')
    expect(timeLeft(at(1_000), now)).toBe('under 1 min left')
  })
  it('gives nothing once the time has passed, when absent, or when unreadable', () => {
    expect(timeLeft(at(-1_000), now)).toBeNull()
    expect(timeLeft(at(0), now)).toBeNull()
    expect(timeLeft(undefined, now)).toBeNull()
    expect(timeLeft('', now)).toBeNull()
    expect(timeLeft('not a time', now)).toBeNull()
  })
})

describe('SCENARIO_INFO', () => {
  const ids = ['cpu-spike', 'oom', 'crashloop', 'http-500', 'shell-injection', 'credential-read', 'network-recon', 'restart-storm']

  it('has plain-language copy for every scenario the controller allows', () => {
    for (const id of ids) {
      const info = SCENARIO_INFO[id]
      expect(info, id).toBeDefined()
      expect(info.title.length, id).toBeGreaterThan(0)
      expect(info.note.length, id).toBeGreaterThan(10)
      expect(['operational', 'security', 'human'], id).toContain(info.kind)
    }
  })
  it('lists each scenario exactly once in the display order', () => {
    expect([...SCENARIO_ORDER].sort()).toEqual([...ids].sort())
  })
})
