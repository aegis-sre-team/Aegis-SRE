import type { Pod } from '../api/types'

export type HeadlineTone = 'ok' | 'warn' | 'bad' | 'defend' | 'neutral'

export interface Headline {
  tone: HeadlineTone
  title: string
  detail: string
}

export interface PodSummary {
  total: number
  healthy: number
  /** Degraded, failed or any status we do not recognise: never counted as fine. */
  attention: number
  failed: number
  quarantined: number
}

/** Finished Job pods (COMPLETED) are neither healthy nor a problem, so they only count towards the total. */
export function summarizePods(pods: Pick<Pod, 'status'>[]): PodSummary {
  const s: PodSummary = { total: pods.length, healthy: 0, attention: 0, failed: 0, quarantined: 0 }
  for (const p of pods) {
    if (p.status === 'HEALTHY') s.healthy++
    else if (p.status === 'QUARANTINED') s.quarantined++
    else if (p.status === 'COMPLETED') continue
    else {
      s.attention++
      if (p.status === 'FAILED') s.failed++
    }
  }
  return s
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many)

/**
 * The one sentence the Overview opens with. Severity order: a decision only a person can make, then a
 * sensor we cannot see through, then failing pods, then contained pods. "Healthy" is only ever said when
 * a reading exists, every sensor answered and nothing needs a person, so it cannot overclaim.
 */
export function statusHeadline(input: {
  hasReading: boolean
  pods: Pick<Pod, 'status'>[]
  sensorsDown: string[]
  waiting: number
  /** Active quarantines from the snapshot. Pod rows can lag behind this, so both are consulted. */
  quarantines: number
}): Headline {
  const { hasReading, pods, sensorsDown, waiting, quarantines } = input
  if (!hasReading) return { tone: 'neutral', title: 'Waiting for the first reading.', detail: 'The dashboard has not received telemetry yet.' }

  if (waiting > 0) {
    return {
      tone: 'warn',
      title: `${waiting} ${plural(waiting, 'incident needs', 'incidents need')} a decision.`,
      detail: 'Aegis stopped before acting. Nothing runs on these until a person decides.',
    }
  }

  if (sensorsDown.length > 0) {
    return {
      tone: 'bad',
      title: plural(sensorsDown.length, 'A sensor is down.', 'Sensors are down.'),
      detail: 'Pod status may be incomplete. Aegis shows “no data” and escalates to a human instead of guessing.',
    }
  }

  const s = summarizePods(pods)
  if (s.attention > 0) {
    return {
      tone: s.failed > 0 ? 'bad' : 'warn',
      title: `${s.attention} ${plural(s.attention, 'pod needs', 'pods need')} attention.`,
      detail: `${s.healthy} of ${s.total} pods are running and ready.`,
    }
  }
  const caged = Math.max(s.quarantined, quarantines)
  if (caged > 0) {
    return {
      tone: 'defend',
      title: `${caged} ${plural(caged, 'pod is', 'pods are')} quarantined.`,
      detail: 'Their network is cut and they are kept alive for forensics. Releasing one is a human decision.',
    }
  }
  if (s.total === 0) return { tone: 'neutral', title: 'No pods found.', detail: 'The controller returned no pods for the managed namespaces.' }

  return {
    tone: 'ok',
    title: 'Everything is healthy.',
    detail: `${s.healthy} ${plural(s.healthy, 'pod is', 'pods are')} running and ready, and nothing is waiting on a person.`,
  }
}
