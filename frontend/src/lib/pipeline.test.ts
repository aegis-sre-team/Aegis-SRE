import { describe, expect, it } from 'vitest'
import type { AuditRow, Incident } from '../api/types'
import { buildChain, matchAudit, outcomeOf, resultOf } from './pipeline'

const incident = (over: Partial<Incident> = {}): Incident => ({
  id: 1,
  incident_id: 'INC-1',
  target_pod: 'web-1',
  problem_type: 'OPERATIONAL_BUG',
  threat_level: 'MEDIUM',
  mitre_technique: null,
  root_cause: 'Memory leak',
  recommended_action: 'RESTART_POD',
  final_action: 'RESTART_POD',
  confidence: 0.91,
  guardrail_approved: true,
  guardrail_reason: 'ok',
  status: 'RESOLVED',
  created_at: '2026-01-01T10:00:00Z',
  ...over,
})

const audit = (over: Partial<AuditRow> = {}): AuditRow => ({
  id: 5,
  timestamp: '2026-01-01T10:00:05Z',
  target_pod: 'web-1',
  problem_type: 'OPERATIONAL_BUG',
  executed_action: 'RESTART_POD',
  execution_success: true,
  status_code: 'SUCCESS',
  details: 'restarted',
  forensics_file: null,
  health_verified: true,
  ...over,
})

describe('buildChain', () => {
  it('marks a healthy remediation as resolved end to end', () => {
    const stages = buildChain(incident(), audit())
    expect(stages.map((s) => s.state)).toEqual(['passed', 'passed', 'passed', 'passed', 'passed'])
    expect(outcomeOf(stages, incident())).toBe('resolved')
  })

  it('stops the chain at a blocked guardrail and never invents an execution', () => {
    const inc = incident({ guardrail_approved: false, final_action: 'ESCALATE' })
    const stages = buildChain(inc, null)
    expect(stages.map((s) => s.state)).toEqual(['passed', 'passed', 'blocked', 'skipped', 'skipped'])
    expect(outcomeOf(stages, inc)).toBe('needs-human')
  })

  it('reports an unverified run as unknown, not passed', () => {
    const stages = buildChain(incident(), audit({ health_verified: null }))
    expect(stages[4].state).toBe('unknown')
  })

  it('never reports a dry run as healed, even if the row says healthy', () => {
    const inc = incident()
    const dry = audit({ status_code: 'COMPLETED_DRY_RUN', details: '[DRY_RUN SUCCESS] ... not performed (dry run)', health_verified: true })
    const stages = buildChain(inc, dry)
    expect(stages[3].dryRun).toBe(true)
    expect(stages[4].state).toBe('unknown')
    expect(outcomeOf(stages, inc)).toBe('dry-run')
  })

  it('trusts the execution record over an optimistic incident row when the action was skipped', () => {
    const inc = incident({ guardrail_approved: true })
    const skipped = audit({ executed_action: 'ESCALATE', execution_success: false, status_code: 'SKIPPED_NOT_APPROVED', details: 'restart cap exceeded' })
    const stages = buildChain(inc, skipped)
    expect(stages.map((s) => s.state)).toEqual(['passed', 'passed', 'blocked', 'skipped', 'skipped'])
    expect(stages[2].detail).toBe('restart cap exceeded')
    expect(outcomeOf(stages, inc)).toBe('needs-human')
    expect(resultOf(skipped)).toBe('escalated')
  })

  it('flags a failed verification', () => {
    const inc = incident()
    const stages = buildChain(inc, audit({ health_verified: false }))
    expect(stages[4].state).toBe('failed')
    expect(outcomeOf(stages, inc)).toBe('failed')
  })

  it('calls a successful quarantine contained', () => {
    const inc = incident({ final_action: 'CILIUM_QUARANTINE_EBPF', problem_type: 'SECURITY_ATTACK' })
    const stages = buildChain(inc, audit({ executed_action: 'CILIUM_QUARANTINE_EBPF', health_verified: null }))
    expect(outcomeOf(stages, inc)).toBe('contained')
  })

  it('notes when the guardrails changed the proposed action', () => {
    const inc = incident({ recommended_action: 'RESTART_POD', final_action: 'CILIUM_QUARANTINE_EBPF' })
    expect(buildChain(inc, null)[2].summary).toMatch(/changed to/i)
  })
})

describe('matchAudit', () => {
  it('picks the first audit row at or after the incident for the same pod', () => {
    const rows = [audit({ id: 9, timestamp: '2026-01-01T09:00:00Z' }), audit({ id: 7 }), audit({ id: 8, timestamp: '2026-01-01T11:00:00Z' })]
    expect(matchAudit(incident(), rows)?.id).toBe(7)
  })

  it('returns null when the pod has no rows', () => {
    expect(matchAudit(incident(), [audit({ target_pod: 'other' })])).toBeNull()
  })
})
