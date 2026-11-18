import type { AuditRow, Incident } from '../api/types'
import { actionLabel, confidenceLabel, problemLabel } from './format'

/** One station on the incident chain. */
export type StageState = 'passed' | 'blocked' | 'failed' | 'skipped' | 'unknown'

export interface Stage {
  key: 'detected' | 'diagnosed' | 'guardrails' | 'acted' | 'verified'
  title: string
  state: StageState
  summary: string
  detail?: string
  /** true when the action only ran as a dry run: nothing changed in a cluster */
  dryRun?: boolean
}

/** The executor skipped this action because the guardrails did not approve it (or the verdict was ESCALATE). */
export const isSkipped = (a: AuditRow): boolean => /^SKIPPED/i.test(a.status_code) || a.executed_action === 'ESCALATE'

/** The action ran in dry-run mode, so it never touched a cluster and health was never checked. */
export const isDryRun = (a: AuditRow): boolean => /dry[_ ]?run/i.test(`${a.status_code} ${a.details ?? ''}`)

export type ResultKind = 'ok' | 'failed' | 'escalated' | 'dry-run'

export function resultOf(a: AuditRow): ResultKind {
  if (isSkipped(a)) return 'escalated'
  if (!a.execution_success) return 'failed'
  if (isDryRun(a)) return 'dry-run'
  return 'ok'
}

/**
 * Picks the audit row that records what the executor did for this incident. The audit table has no
 * incident id, so the match is by pod and time: the first row at or after the incident, else null.
 */
export function matchAudit(incident: Incident, audits: AuditRow[]): AuditRow | null {
  const forPod = audits.filter((a) => a.target_pod === incident.target_pod || a.target_pod.endsWith(`/${incident.target_pod}`))
  if (forPod.length === 0) return null
  const since = incident.created_at ?? ''
  const after = forPod.filter((a) => a.timestamp >= since).sort((a, b) => a.id - b.id)
  return after[0] ?? null
}

export function buildChain(incident: Incident, audit: AuditRow | null): Stage[] {
  // The incident row is written before the guardrails run, so the execution record is the better
  // witness: if the executor skipped the action, the guardrails did not approve it.
  const stoppedByGuardrails = (audit !== null && isSkipped(audit)) || incident.final_action === 'ESCALATE'
  const approved = stoppedByGuardrails ? false : incident.guardrail_approved
  const changed =
    incident.recommended_action && incident.final_action && incident.recommended_action !== incident.final_action

  const detected: Stage = {
    key: 'detected',
    title: 'Detected',
    state: 'passed',
    summary: problemLabel(incident.problem_type),
    detail: incident.mitre_technique ?? undefined,
  }

  const diagnosed: Stage = {
    key: 'diagnosed',
    title: 'Diagnosed',
    state: 'passed',
    summary: `${actionLabel(incident.recommended_action)} at ${confidenceLabel(incident.confidence)} confidence`,
    detail: incident.root_cause ?? undefined,
  }

  const guardrails: Stage = {
    key: 'guardrails',
    title: 'Guardrails',
    state: approved === true ? 'passed' : approved === false ? 'blocked' : 'unknown',
    summary:
      approved === true
        ? changed
          ? `Approved, changed to ${actionLabel(incident.final_action)}`
          : 'Approved as proposed'
        : approved === false
          ? 'Blocked, sent to a human'
          : 'No decision recorded',
    detail: (stoppedByGuardrails ? audit?.details : null) || incident.guardrail_reason || undefined,
  }

  if (approved === false) {
    return [
      detected,
      diagnosed,
      guardrails,
      { key: 'acted', title: 'Acted', state: 'skipped', summary: 'Nothing ran' },
      { key: 'verified', title: 'Verified', state: 'skipped', summary: 'Nothing to verify' },
    ]
  }

  const dry = audit !== null && isDryRun(audit)

  const acted: Stage = !audit
    ? { key: 'acted', title: 'Acted', state: 'unknown', summary: 'No execution record found' }
    : {
        key: 'acted',
        title: 'Acted',
        state: audit.execution_success ? 'passed' : 'failed',
        summary: audit.execution_success
          ? `${actionLabel(audit.executed_action)}: ${dry ? 'simulated, nothing changed' : 'done'}`
          : `${actionLabel(audit.executed_action)}: failed`,
        detail: [audit.status_code, audit.details].filter(Boolean).join(' · ') || undefined,
        dryRun: dry,
      }

  const verified: Stage = !audit
    ? { key: 'verified', title: 'Verified', state: 'unknown', summary: 'No execution record found' }
    : !audit.execution_success
      ? { key: 'verified', title: 'Verified', state: 'skipped', summary: 'Action failed, not checked' }
      : dry
        ? { key: 'verified', title: 'Verified', state: 'unknown', summary: 'Not checked in a dry run', dryRun: true }
        : audit.health_verified === true
          ? { key: 'verified', title: 'Verified', state: 'passed', summary: 'Workload is healthy again' }
          : audit.health_verified === false
            ? { key: 'verified', title: 'Verified', state: 'failed', summary: 'Still unhealthy, escalated' }
            : { key: 'verified', title: 'Verified', state: 'unknown', summary: 'Health was not checked' }

  return [detected, diagnosed, guardrails, acted, verified]
}

/** Overall outcome for list rows. */
export type Outcome = 'resolved' | 'contained' | 'needs-human' | 'failed' | 'dry-run' | 'open'

export function outcomeOf(stages: Stage[], incident: Incident): Outcome {
  const g = stages.find((s) => s.key === 'guardrails')
  const a = stages.find((s) => s.key === 'acted')
  const v = stages.find((s) => s.key === 'verified')
  if (g?.state === 'blocked') return 'needs-human'
  if (a?.state === 'failed' || v?.state === 'failed') return 'failed'
  if (a?.state === 'passed' && a.dryRun) return 'dry-run'
  if (a?.state === 'passed' && incident.final_action === 'CILIUM_QUARANTINE_EBPF') return 'contained'
  if (a?.state === 'passed') return 'resolved'
  return 'open'
}

export const OUTCOME_LABEL: Record<Outcome, string> = {
  resolved: 'Resolved',
  contained: 'Contained',
  'needs-human': 'Needs a human',
  failed: 'Failed',
  'dry-run': 'Dry run',
  open: 'Open',
}
