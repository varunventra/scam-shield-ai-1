import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Lock, Loader2 } from 'lucide-react'
import { adminLogin, adminSessionActive } from '../lib/api'
import { useDarkMode } from '../hooks/useDarkMode'

/**
 * Gates the dashboard behind a server-side admin session.
 *
 * The admin key is typed here once and POSTed to /api/v1/admin/login, which
 * returns an httpOnly cookie. It is never written to localStorage, never put in
 * a VITE_ env var, and therefore never ends up in the shipped bundle where any
 * visitor could read it.
 */
export default function AdminGate({ children }) {
  const dark = useDarkMode()
  const [state, setState] = useState('checking')   // checking | locked | open
  const [key, setKey] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const C = dark
    ? { bg: '#09090b', surface: '#101013', line: '#27272a', text: '#fafafa', muted: '#8b8b94', input: '#16161a' }
    : { bg: '#ffffff', surface: '#fafafa', line: '#e4e4e7', text: '#111111', muted: '#71717a', input: '#ffffff' }

  useEffect(() => {
    let cancelled = false
    adminSessionActive().then((active) => {
      if (!cancelled) setState(active ? 'open' : 'locked')
    })
    return () => { cancelled = true }
  }, [])

  const submit = useCallback(async (e) => {
    e.preventDefault()
    if (!key.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await adminLogin(key.trim())
      setKey('')
      setState('open')
    } catch (err) {
      setError(
        err?.response?.status === 401
          ? 'Key rejected.'
          : err?.response?.status === 429
            ? 'Too many attempts. Wait a minute.'
            : `Backend unreachable: ${err?.message || 'unknown error'}`
      )
    }
    setSubmitting(false)
  }, [key])

  if (state === 'open') return children

  if (state === 'checking') {
    return (
      <div className="flex h-screen items-center justify-center" style={{ background: C.bg }}>
        <Loader2 size={16} className="animate-spin" style={{ color: C.muted }} />
      </div>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center px-6" style={{ background: C.bg }}>
      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
        className="w-full max-w-sm p-7"
        style={{ background: C.surface, border: `1px solid ${C.line}`, borderRadius: 4 }}
      >
        <div className="flex items-center gap-2">
          <Lock size={14} style={{ color: C.muted }} />
          <h1 className="text-sm font-semibold" style={{ color: C.text }}>Admin access</h1>
        </div>

        <p className="mt-2 text-xs leading-relaxed" style={{ color: C.muted }}>
          Enter the backend <span className="font-mono">ADMIN_API_KEY</span>. It is exchanged for a
          session cookie and is never stored in the browser.
        </p>

        <input
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="admin key"
          autoFocus
          autoComplete="current-password"
          className="mt-5 w-full px-3 py-2 text-xs font-mono outline-none"
          style={{
            background: C.input,
            border: `1px solid ${error ? '#b91c1c' : C.line}`,
            borderRadius: 4,
            color: C.text,
          }}
        />

        {error && (
          <p className="mt-2 text-xs font-mono" style={{ color: '#c87070' }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={submitting || !key.trim()}
          className="mt-4 w-full py-2 text-xs font-semibold transition-opacity disabled:opacity-40"
          style={{ background: '#3b82f6', color: '#ffffff', borderRadius: 4 }}
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </motion.form>
    </div>
  )
}
