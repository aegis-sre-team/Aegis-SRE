import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { CircleAlert, CircleCheck, Info, X } from 'lucide-react'
import { ApiError, getToken, setToken } from '../api/client'
import { Dialog } from '../components/Dialog'

type ToastKind = 'ok' | 'error' | 'info'
interface Toast {
  id: number
  kind: ToastKind
  text: string
}

interface Feedback {
  toast: (kind: ToastKind, text: string) => void
  /** Runs a mutating call. If the server wants a dashboard token, asks for it once and retries. */
  withAuth: <T>(fn: () => Promise<T>) => Promise<T>
}

const FeedbackContext = createContext<Feedback | null>(null)

export function useFeedback(): Feedback {
  const c = useContext(FeedbackContext)
  if (!c) throw new Error('useFeedback must be used inside <FeedbackProvider>')
  return c
}

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const seq = useRef(0)
  const [asking, setAsking] = useState<null | ((t: string | null) => void)>(null)
  const [draft, setDraft] = useState('')

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), [])

  const toast = useCallback(
    (kind: ToastKind, text: string) => {
      const id = ++seq.current
      setToasts((t) => [...t.slice(-3), { id, kind, text }])
      window.setTimeout(() => dismiss(id), kind === 'error' ? 9000 : 5000)
    },
    [dismiss],
  )

  const askToken = useCallback(
    () =>
      new Promise<string | null>((resolve) => {
        setDraft('')
        setAsking(() => resolve)
      }),
    [],
  )

  const withAuth = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn()
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {
          const t = await askToken()
          if (!t) throw e
          setToken(t)
          try {
            return await fn()
          } catch (e2) {
            if (e2 instanceof ApiError && e2.status === 401) setToken(null)
            throw e2
          }
        }
        throw e
      }
    },
    [askToken],
  )

  const value = useMemo(() => ({ toast, withAuth }), [toast, withAuth])
  const close = (t: string | null) => {
    asking?.(t)
    setAsking(null)
  }

  return (
    <FeedbackContext.Provider value={value}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`}>
            {t.kind === 'ok' ? <CircleCheck size={18} /> : t.kind === 'error' ? <CircleAlert size={18} /> : <Info size={18} />}
            <span>{t.text}</span>
            <button className="icon-btn" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
              <X size={16} />
            </button>
          </div>
        ))}
      </div>
      {asking && (
        <Dialog title="Dashboard token required" onClose={() => close(null)} width={420}>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              close(draft.trim() || null)
            }}
          >
            <p className="muted">
              This dashboard only lets people with the shared token change the cluster. Enter it once; it is kept for this tab only.
            </p>
            <label className="field">
              <span>Token</span>
              <input autoFocus type="password" value={draft} onChange={(e) => setDraft(e.target.value)} autoComplete="off" />
            </label>
            <div className="row end gap">
              <button type="button" className="btn" onClick={() => close(null)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={!draft.trim()}>
                Continue
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </FeedbackContext.Provider>
  )
}

export { getToken }
