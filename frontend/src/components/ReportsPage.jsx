import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { fetchSessions, downloadForensicPDF } from '../lib/api'
import { Download, FileText, AlertCircle, RefreshCw, Shield } from 'lucide-react'
import { useDarkMode } from '../hooks/useDarkMode'
import { TYPE_LABELS, SCAM_COLORS } from '../lib/labels'

// Muted, desaturated risk styles — border + text only, no bright fills
const RISK_STYLE = {
  high:   { color: '#c87070', border: '#5a2a2a', dot: '#7f3030', label: 'HIGH'   },
  medium: { color: '#b08050', border: '#4a3520', dot: '#7a5020', label: 'MEDIUM' },
  low:    { color: '#4a7a5a', border: '#1e3a2a', dot: '#2a5a3a', label: 'LOW'    },
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) +
    ' · ' + d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })
}

function formatDuration(secs) {
  if (!secs) return null
  const m = Math.floor(secs / 60)
  const s = secs % 60
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}


function ReportRow({ session, index, dark }) {
  const [status, setStatus] = useState('idle')

  const borderColor = dark ? '#27272a' : '#e4e4e7'
  const pageBg      = dark ? '#09090b' : '#ffffff'
  const bodyText    = dark ? '#fafafa'  : '#111111'
  const mutedText   = '#71717a'
  const cardBg      = dark ? '#0f0f11' : '#fafafa'

  const intelCount    = Object.values(session.intelligence || {}).flat().length
  const risk          = RISK_STYLE[session.riskLevel] || null
  const duration      = formatDuration(session.durationSeconds)
  const typeLabel     = TYPE_LABELS[session.scamType] || (session.scamType || 'Unknown').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
  const typeColor     = SCAM_COLORS[session.scamType] || '#52525b'

  const handleDownload = async () => {
    setStatus('downloading')
    try {
      const blob = await downloadForensicPDF(session.sessionId)
      if (!blob) { setStatus('not_ready'); return }
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scamshield-${session.sessionId.slice(0, 8)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
      setStatus('idle')
    } catch {
      setStatus('error')
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className="flex items-center gap-4 p-5"
      style={{ background: cardBg, border: `1px solid ${borderColor}`, borderRadius: 6 }}
    >
      {/* Icon colored by scam type */}
      <div
        className="w-10 h-10 flex items-center justify-center flex-shrink-0"
        style={{ border: `1px solid ${typeColor}30`, borderRadius: 4, background: `${typeColor}10` }}
      >
        <FileText size={15} style={{ color: typeColor }} />
      </div>

      {/* Main info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="text-sm font-semibold truncate" style={{ color: bodyText }}>{typeLabel}</span>
          {/* SCAM badge — muted red */}
          <span className="px-2 py-0.5 text-[10px] font-mono font-semibold" style={{ border: '1px solid #5a2a2a', color: '#c87070', borderRadius: 3 }}>
            SCAM
          </span>
          {/* Risk badge — dot + label for visual clarity */}
          {risk && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono font-semibold" style={{ border: `1px solid ${risk.border}`, color: risk.color, borderRadius: 3 }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: risk.dot, flexShrink: 0, display: 'inline-block' }} />
              {risk.label}
            </span>
          )}
          {/* Repeat badge — muted amber */}
          {session.repeatScammer && (
            <span className="px-2 py-0.5 text-[10px] font-mono font-semibold" style={{ border: '1px solid #4a3520', color: '#b08050', borderRadius: 3 }}>
              ↺ REPEAT{session.repeatCount > 0 ? ` ×${session.repeatCount}` : ''}
            </span>
          )}
        </div>

        <p className="text-[11px] font-mono mb-1.5" style={{ color: mutedText }}>
          {session.sessionId.slice(0, 24)}…
        </p>

        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-[10px] font-mono" style={{ color: mutedText }}>{formatDate(session.startTime)}</span>
          <span className="text-[10px] font-mono" style={{ color: mutedText }}>·</span>
          <span className="text-[10px] font-mono" style={{ color: mutedText }}>{session.turnCount || 0} turns</span>
          {duration && <>
            <span className="text-[10px] font-mono" style={{ color: mutedText }}>·</span>
            <span className="text-[10px] font-mono" style={{ color: mutedText }}>{duration}</span>
          </>}
          {intelCount > 0 && <>
            <span className="text-[10px] font-mono" style={{ color: mutedText }}>·</span>
            <span className="text-[10px] font-mono font-semibold" style={{ color: '#3b82f6' }}>{intelCount} intel</span>
          </>}
          {session.confidence && <>
            <span className="text-[10px] font-mono" style={{ color: mutedText }}>·</span>
            <span className="text-[10px] font-mono font-semibold" style={{ color: bodyText }}>{session.confidence}%</span>
          </>}
        </div>
      </div>

      {/* Download */}
      <div className="flex-shrink-0">
        {status === 'not_ready' ? (
          <div className="flex items-center gap-1.5 px-3 py-1.5" style={{ border: `1px solid ${borderColor}`, color: mutedText, borderRadius: 4 }}>
            <AlertCircle size={12} />
            <span className="text-xs font-mono">Not ready</span>
          </div>
        ) : (
          <button
            onClick={handleDownload}
            disabled={status === 'downloading'}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-semibold disabled:opacity-50 transition-opacity hover:opacity-80"
            style={{ background: bodyText, color: dark ? '#09090b' : '#ffffff', borderRadius: 4 }}
          >
            <Download size={12} />
            {status === 'downloading' ? 'Saving…' : status === 'error' ? 'Retry' : 'PDF'}
          </button>
        )}
      </div>
    </motion.div>
  )
}

export default function ReportsPage() {
  const dark = useDarkMode()
  const [sessions, setSessions] = useState([])
  const [loading, setLoading]   = useState(false)
  const [fetchError, setFetchError] = useState(null)

  const borderColor = dark ? '#27272a' : '#e4e4e7'
  const pageBg      = dark ? '#09090b' : '#ffffff'
  const bodyText    = dark ? '#fafafa'  : '#111111'
  const mutedText   = '#71717a'

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await fetchSessions(100)
      setSessions(data)
    } catch (err) {
      const status = err?.response?.status
      setFetchError(status === 401 ? 'Admin session expired — log in again' : `Backend error: ${err?.message || 'unknown'}`)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [load])

  return (
    <div className="h-full flex flex-col" style={{ background: pageBg }}>
      {/* Header */}
      <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: `1px solid ${borderColor}` }}>
        <div>
          <h1 className="font-bold text-lg" style={{ color: bodyText }}>Forensic Reports</h1>
          <p className="text-xs font-mono mt-0.5" style={{ color: mutedText }}>
            {sessions.length} session{sessions.length !== 1 ? 's' : ''} · PDFs generated after 3+ turns
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono transition-colors"
          style={{ color: mutedText, border: `1px solid ${borderColor}`, borderRadius: 4, opacity: loading ? 0.5 : 1 }}
          onMouseEnter={e => { if (!loading) { e.currentTarget.style.color = bodyText; e.currentTarget.style.borderColor = bodyText } }}
          onMouseLeave={e => { e.currentTarget.style.color = mutedText; e.currentTarget.style.borderColor = borderColor }}
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* API error banner */}
      {fetchError && (
        <div className="px-5 py-2.5 flex items-center gap-2 flex-shrink-0" style={{ background: '#1f0606', borderBottom: '1px solid #7f1d1d' }}>
          <span className="text-xs font-mono" style={{ color: '#fca5a5' }}>⚠ {fetchError}</span>
          <button onClick={() => setFetchError(null)} className="ml-auto text-xs font-mono" style={{ color: '#71717a' }}>dismiss</button>
        </div>
      )}

      {/* List */}
      <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
        {loading && sessions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2">
            <RefreshCw size={16} className="animate-spin" style={{ color: mutedText }} />
            <p className="text-sm font-mono" style={{ color: mutedText }}>Loading reports…</p>
          </div>
        ) : sessions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-8 py-16 gap-3">
            <Shield size={28} style={{ color: borderColor }} />
            <p className="font-semibold" style={{ color: bodyText }}>{fetchError ? 'Failed to load sessions' : 'No sessions yet'}</p>
            <p className="text-sm font-mono max-w-xs" style={{ color: mutedText }}>
              {fetchError ? 'Check that the backend is running and admin key is correct.' : 'Run a session from the Auto tab or Demo page and it will appear here automatically.'}
            </p>
          </div>
        ) : (
          <div className="p-5 space-y-3">
            {sessions.map((s, i) => (
              <ReportRow key={s.sessionId} session={s} index={i} dark={dark} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
