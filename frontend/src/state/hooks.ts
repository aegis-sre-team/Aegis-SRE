import { useCallback, useEffect, useRef, useState } from 'react'
import { useAegis } from './AegisProvider'

export interface Resource<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

/**
 * Fetches persisted data and refetches it when the server reports a change (dataVersion) or on a slow
 * timer as a safety net. Keeps the previous data on screen while reloading so lists do not flicker.
 */
export function useResource<T>(load: () => Promise<T>, key: string = '', intervalMs = 20000): Resource<T> {
  const { state } = useAegis()
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const loadRef = useRef(load)
  loadRef.current = load

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    loadRef
      .current()
      .then((d) => {
        if (!cancelled) {
          setData(d)
          setError(null)
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [key, state.dataVersion, tick])

  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), intervalMs)
    return () => window.clearInterval(t)
  }, [intervalMs])

  const reload = useCallback(() => setTick((n) => n + 1), [])
  return { data, error, loading, reload }
}
