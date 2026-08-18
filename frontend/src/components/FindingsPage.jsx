import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchSessions, exportIntelligence } from '../lib/api'
import { RefreshCw, Phone, CreditCard, Link, Building2, Search, X, BarChart2, List, Download } from 'lucide-react'
import { useDarkMode } from '../hooks/useDarkMode'
import { TYPE_LABELS, SCAM_COLORS } from '../lib/labels'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'

// Re-exported for existing importers (e.g. ReportsPage). Canonical source: lib/labels.
export { SCAM_COLORS }

function formatDate(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
}

function formatDuration(secs) {
  if (!secs) return '—'
  const m = Math.floor(secs / 60)
  const s = secs % 60
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

function confidenceColor(score) {
  if (score >= 85) return { bar: '#ef4444', text: '#ef4444' }
  if (score >= 70) return { bar: '#f97316', text: '#f97316' }
  return { bar: '#22c55e', text: '#22c55e' }
}

function IntelSummary({ intel, dark, bodyText }) {
  const items = [
    { key: 'phoneNumbers',  icon: Phone,     color: '#3b82f6' },
    { key: 'upiIds',        icon: CreditCard, color: '#3b82f6' },
    { key: 'bankAccounts',  icon: Building2,  color: '#3b82f6' },
    { key: 'phishingLinks', icon: Link,       color: '#ef4444' },
  ]
  const safeIntel = intel || {}
  const hasAny = items.some(i => (safeIntel[i.key] || []).length > 0)
  if (!hasAny) return <p className="text-xs font-mono" style={{ color: '#71717a' }}>No intel extracted</p>
  return (
    <div className="flex items-center gap-3 flex-wrap">
      {items.map(({ key, icon: Icon, color }) => {
        const count = (safeIntel[key] || []).length
        if (!count) return null
        return (
          <div key={key} className="flex items-center gap-1">
            <Icon size={11} style={{ color }} />
            <span className="text-xs font-mono font-semibold" style={{ color: bodyText }}>{count}</span>
          </div>
        )
      })}
    </div>
  )
}

function ChartsPanel({ sessions, dark }) {
  const pieData = useMemo(() => {
    const counts = {}
    sessions.forEach(s => {
      const key = s.scamType || 'manual'
      counts[key] = (counts[key] || 0) + 1
    })
    return Object.entries(counts).map(([key, value]) => ({
      key,
      name: TYPE_LABELS[key] || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      value,
      color: SCAM_COLORS[key] || '#52525b',
    }))
  }, [sessions])

  const barData = useMemo(() => (
    sessions.slice(0, 10).reverse().map((s, i) => ({
      name: `S${i + 1}`,
      intel: Object.values(s.intelligence || {}).filter(v => Array.isArray(v)).flat().length,
      confidence: s.confidence || 0,
    }))
  ), [sessions])

  const borderColor = dark ? '#27272a' : '#e4e4e7'
  const pageBg      = dark ? '#09090b' : '#ffffff'
  const bodyText    = dark ? '#fafafa'  : '#111111'
  const mutedText   = '#71717a'
  const gridColor   = borderColor

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null
    return (
      <div className="px-3 py-2 text-xs font-mono" style={{ background: pageBg, border: `1px solid ${borderColor}`, borderRadius: 4 }}>
        <p className="font-semibold mb-1" style={{ color: bodyText }}>{label}</p>
        {payload.map(p => (
          <p key={p.name} style={{ color: mutedText }}>{p.name}: {p.value}</p>
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 gap-4 p-6">
      <div className="p-5" style={{ background: dark ? '#0f0f11' : '#fafafa', border: `1px solid ${borderColor}`, borderRadius: 6 }}>
        <p className="text-[10px] uppercase tracking-widest font-mono font-semibold mb-4" style={{ color: mutedText }}>Scam Type Breakdown</p>
        <div className="flex items-center gap-5">
          <ResponsiveContainer width={130} height={130}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={36} outerRadius={58} paddingAngle={3} dataKey="value">
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-col gap-2 min-w-0 flex-1">
            {pieData.map(entry => (
              <div key={entry.name} className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 flex-shrink-0 rounded-sm" style={{ background: entry.color }} />
                <span className="text-xs font-mono truncate flex-1" style={{ color: mutedText }}>{entry.name}</span>
                <span className="text-xs font-mono font-bold flex-shrink-0" style={{ color: bodyText }}>{entry.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="p-5" style={{ background: dark ? '#0f0f11' : '#fafafa', border: `1px solid ${borderColor}`, borderRadius: 6 }}>
        <p className="text-[10px] uppercase tracking-widest font-mono font-semibold mb-4" style={{ color: mutedText }}>Intel Items · Last 10 Sessions</p>
        <ResponsiveContainer width="100%" height={130}>
          <BarChart data={barData} barSize={16}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
            <XAxis dataKey="name" tick={{ fontSize: 10, fill: mutedText, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 10, fill: mutedText, fontFamily: 'monospace' }} axisLine={false} tickLine={false} width={24} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="intel" name="Intel Items" fill="#4f46e5" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default function FindingsPage() {
  const dark = useDarkMode()
  const [sessions, setSessions]   = useState([])
  const [filter, setFilter]       = useState('All')
  const [expanded, setExpanded]   = useState(null)
  const [search, setSearch]       = useState('')
  const [view, setView]           = useState('list')
  const [minConf, setMinConf]     = useState(0)
  const [repeatsOnly, setRepeatsOnly] = useState(false)
  const [loading, setLoading]     = useState(false)
  const [fetchError, setFetchError] = useState(null)

  const borderColor = dark ? '#27272a' : '#e4e4e7'
  const pageBg      = dark ? '#09090b' : '#ffffff'
  const bodyText    = dark ? '#fafafa'  : '#111111'
  const mutedText   = '#71717a'

  const loadSessions = useCallback(async () => {
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
    loadSessions()
    const interval = setInterval(loadSessions, 30000)
    return () => clearInterval(interval)
  }, [loadSessions])

  const activeTypes = ['All', ...new Set(sessions.map(s => s.scamType || 'manual').filter(Boolean))]

  const filtered = useMemo(() => {
    let list = sessions
    if (filter !== 'All') list = list.filter(s => (s.scamType || 'manual') === filter)
    if (minConf > 0)       list = list.filter(s => (s.confidence || 0) >= minConf)
    if (repeatsOnly) {
      // Most-repeated offenders first
      list = [...list.filter(s => s.repeatScammer)].sort((a, b) => (b.repeatCount || 0) - (a.repeatCount || 0))
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      list = list.filter(s => {
        const intelStr = Object.values(s.intelligence || {}).flat().join(' ').toLowerCase()
        return (
          s.sessionId.toLowerCase().includes(q) ||
          (s.scamType || '').toLowerCase().includes(q) ||
          intelStr.includes(q)
        )
      })
    }
    return list
  }, [sessions, filter, minConf, search, repeatsOnly])

  return (
    <div className="h-full flex flex-col" style={{ background: pageBg }}>
      {/* Header */}
      <div
        className="px-6 py-4 flex items-center justify-between flex-shrink-0"
        style={{ background: pageBg, borderBottom: `1px solid ${borderColor}` }}
      >
        <div>
          <h1 className="font-bold text-lg" style={{ color: bodyText }}>Findings</h1>
          <p className="text-xs font-mono mt-0.5" style={{ color: mutedText }}>{sessions.length} session{sessions.length !== 1 ? 's' : ''} recorded</p>
        </div>
        <div className="flex items-center gap-2">
          {/* View toggle */}
          <div className="flex items-center gap-0.5 p-1" style={{ border: `1px solid ${borderColor}`, borderRadius: 4 }} role="group" aria-label="View mode">
            <button
              onClick={() => setView('list')}
              aria-label="List view"
              aria-pressed={view === 'list'}
              className="p-1.5 transition-colors"
              style={{
                background: view === 'list' ? bodyText : 'transparent',
                borderRadius: 2,
              }}
            >
              <List size={13} aria-hidden="true" style={{ color: view === 'list' ? (dark ? '#09090b' : '#ffffff') : mutedText }} />
            </button>
            <button
              onClick={() => setView('charts')}
              aria-label="Charts view"
              aria-pressed={view === 'charts'}
              className="p-1.5 transition-colors"
              style={{
                background: view === 'charts' ? bodyText : 'transparent',
                borderRadius: 2,
              }}
            >
              <BarChart2 size={13} aria-hidden="true" style={{ color: view === 'charts' ? (dark ? '#09090b' : '#ffffff') : mutedText }} />
            </button>
          </div>

          <button
            onClick={loadSessions}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono transition-colors"
            style={{ color: mutedText, border: `1px solid ${borderColor}`, borderRadius: 4, background: 'transparent', opacity: loading ? 0.5 : 1 }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.color = bodyText; e.currentTarget.style.borderColor = bodyText } }}
            onMouseLeave={e => { e.currentTarget.style.color = mutedText; e.currentTarget.style.borderColor = borderColor }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {sessions.length > 0 && (
        /* Single unified toolbar: search + filter chips + confidence — one row */
        <div
          className="px-5 py-2.5 flex items-center gap-3 flex-shrink-0 flex-wrap"
          style={{ background: pageBg, borderBottom: `1px solid ${borderColor}` }}
        >
          {/* Search */}
          <div
            className="flex items-center gap-2 px-2.5 py-1.5"
            style={{ border: `1px solid ${borderColor}`, borderRadius: 4, background: pageBg, minWidth: 180 }}
          >
            <Search size={11} style={{ color: mutedText, flexShrink: 0 }} />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search sessions, intel, scam type…"
              aria-label="Search sessions"
              className="text-xs font-mono bg-transparent outline-none w-40"
              style={{ color: bodyText }}
            />
            {search && (
              <button onClick={() => setSearch('')} aria-label="Clear search">
                <X size={10} aria-hidden="true" style={{ color: mutedText }} />
              </button>
            )}
          </div>

          {/* Divider */}
          <div className="w-px self-stretch" style={{ background: borderColor }} />

          {/* Filter chips */}
          <div className="flex items-center gap-1.5 flex-wrap">
            {activeTypes.map(type => (
              <button
                key={type}
                onClick={() => setFilter(type)}
                className="px-2.5 py-1 text-[10px] font-mono font-medium transition-colors"
                style={filter === type
                  ? { background: bodyText, color: dark ? '#09090b' : '#ffffff', border: `1px solid ${bodyText}`, borderRadius: 3 }
                  : { background: 'transparent', color: mutedText, border: `1px solid ${borderColor}`, borderRadius: 3 }
                }
              >
                {TYPE_LABELS[type] || type}
              </button>
            ))}
          </div>

          {/* Repeat-offender filter + confidence filter pushed to right */}
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => setRepeatsOnly(v => !v)}
              aria-pressed={repeatsOnly}
              aria-label="Show repeat offenders only, most repeated first"
              className="px-2.5 py-1 text-[10px] font-mono font-semibold transition-colors"
              style={repeatsOnly
                ? { background: '#b45309', color: '#ffffff', border: '1px solid #b45309', borderRadius: 3 }
                : { background: 'transparent', color: '#b45309', border: '1px solid #b45309', borderRadius: 3 }
              }
            >
              ↺ REPEATS
            </button>
            <select
              value={minConf}
              onChange={e => setMinConf(Number(e.target.value))}
              aria-label="Minimum confidence filter"
              className="text-[10px] font-mono px-2 py-1.5 outline-none"
              style={{ background: pageBg, color: mutedText, border: `1px solid ${borderColor}`, borderRadius: 4 }}
            >
              <option value={0}>Any confidence</option>
              <option value={70}>70%+</option>
              <option value={80}>80%+</option>
              <option value={90}>90%+</option>
            </select>
          </div>
        </div>
      )}

      {/* API error banner */}
      {fetchError && (
        <div className="px-5 py-2.5 flex items-center gap-2 flex-shrink-0" style={{ background: '#1f0606', borderBottom: '1px solid #7f1d1d' }}>
          <span className="text-xs font-mono" style={{ color: '#fca5a5' }}>⚠ {fetchError}</span>
          <button onClick={() => setFetchError(null)} className="ml-auto text-xs font-mono" style={{ color: '#71717a' }}>dismiss</button>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto" style={{ background: pageBg, scrollbarWidth: 'thin' }}>
        {sessions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-8 py-16">
            <p className="font-semibold mb-1" style={{ color: bodyText }}>{loading ? 'Loading sessions…' : fetchError ? 'Failed to load sessions' : 'No sessions found'}</p>
            <p className="text-sm font-mono" style={{ color: mutedText }}>{loading ? '' : fetchError ? 'Check that the backend is running and ADMIN_API_KEY matches.' : 'Sessions will appear here once recorded in the database.'}</p>
          </div>
        ) : view === 'charts' ? (
          <ChartsPanel sessions={sessions} dark={dark} />
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-8 py-16">
            <p className="font-semibold mb-1" style={{ color: bodyText }}>No matches</p>
            <p className="text-sm font-mono" style={{ color: mutedText }}>Try adjusting your filters or search query.</p>
          </div>
        ) : (
          <div className="p-5 space-y-3">
            <AnimatePresence>
              {filtered.map((s, i) => {
                const colors   = confidenceColor(s.confidence || 0)
                const isOpen   = expanded === s.sessionId
                const intelItems = Object.values(s.intelligence || {}).filter(v => Array.isArray(v)).flat().length
                const typeColor  = SCAM_COLORS[s.scamType] || '#52525b'
                const typeLabel  = s.scamType
                  ? (TYPE_LABELS[s.scamType] || s.scamType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()))
                  : 'Unknown'
                return (
                  <motion.div
                    key={s.sessionId}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className="overflow-hidden cursor-pointer"
                    style={{
                      background: dark ? '#0f0f11' : '#fafafa',
                      border: `1px solid ${isOpen ? typeColor : borderColor}`,
                      borderRadius: 6,
                    }}
                    role="button"
                    tabIndex={0}
                    aria-expanded={isOpen}
                    aria-label={`${typeLabel} session, ${intelItems} intel item${intelItems !== 1 ? 's' : ''}. Activate to ${isOpen ? 'collapse' : 'expand'} details.`}
                    onClick={() => setExpanded(isOpen ? null : s.sessionId)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setExpanded(isOpen ? null : s.sessionId)
                      }
                    }}
                  >
                    <div className="p-5">
                      {/* Top row: type label + date */}
                      <div className="flex items-start justify-between gap-3 mb-2.5">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: typeColor }} />
                          <span className="text-sm font-bold" style={{ color: bodyText }}>{typeLabel}</span>
                          {s.confidence !== null && (
                            <span
                              className="px-2 py-0.5 text-[11px] font-mono font-semibold"
                              style={{ border: `1px solid ${colors.text}`, color: colors.text, borderRadius: 3 }}
                            >
                              {s.confidence}%
                            </span>
                          )}
                          {s.repeatScammer && (
                            <span className="px-2 py-0.5 text-[11px] font-mono font-semibold" style={{ border: '1px solid #b45309', color: '#b45309', borderRadius: 3 }}>
                              ↺ REPEAT{s.repeatCount > 0 ? ` ×${s.repeatCount}` : ''}
                            </span>
                          )}
                        </div>
                        <p className="text-xs font-mono flex-shrink-0" style={{ color: mutedText }}>{formatDate(s.startTime)}</p>
                      </div>

                      {/* Session ID */}
                      <p className="text-xs font-mono mb-3" style={{ color: mutedText }}>{s.sessionId.slice(0, 32)}…</p>

                      <div className="flex items-center justify-between gap-3">
                        {/* Detection score bar */}
                        <div className="flex-1 overflow-hidden" style={{ height: 4, background: borderColor, borderRadius: 99 }}>
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${s.confidence ?? 0}%` }}
                            transition={{ delay: i * 0.03 + 0.1, duration: 0.5, ease: 'easeOut' }}
                            className="h-full"
                            style={{ background: colors.bar, borderRadius: 99 }}
                          />
                        </div>
                        <div className="flex items-center gap-4 flex-shrink-0">
                          <span className="text-xs font-mono" style={{ color: mutedText }}>{s.turnCount} turns</span>
                          {s.durationSeconds > 0 && <span className="text-xs font-mono" style={{ color: mutedText }}>{formatDuration(s.durationSeconds)}</span>}
                          <IntelSummary intel={s.intelligence || {}} dark={dark} bodyText={bodyText} />
                        </div>
                      </div>
                    </div>

                    {/* Expanded detail */}
                    <AnimatePresence>
                      {isOpen && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.18 }}
                          className="overflow-hidden"
                          style={{ borderTop: `1px solid ${borderColor}` }}
                        >
                          <div className="p-4" style={{ background: dark ? '#18181b' : '#f4f4f5' }}>
                            <div className="flex items-center justify-between mb-3">
                              <p className="text-[10px] uppercase tracking-widest font-mono font-semibold" style={{ color: mutedText }}>
                                Extracted Intelligence · {intelItems} item{intelItems !== 1 ? 's' : ''}
                              </p>
                              {intelItems > 0 && (
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={() => exportIntelligence(s.sessionId, 'csv')}
                                    className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono font-semibold uppercase tracking-wider"
                                    style={{ background: pageBg, border: `1px solid ${borderColor}`, borderRadius: 3, color: bodyText, cursor: 'pointer' }}
                                  >
                                    <Download size={11} /> CSV
                                  </button>
                                  <button
                                    onClick={() => exportIntelligence(s.sessionId, 'json')}
                                    className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono font-semibold uppercase tracking-wider"
                                    style={{ background: pageBg, border: `1px solid ${borderColor}`, borderRadius: 3, color: bodyText, cursor: 'pointer' }}
                                  >
                                    <Download size={11} /> JSON
                                  </button>
                                </div>
                              )}
                            </div>
                            {intelItems === 0 ? (
                              <p className="text-xs font-mono" style={{ color: mutedText }}>No intelligence extracted in this session.</p>
                            ) : (
                              <div className="space-y-2.5">
                                {Object.entries(s.intelligence || {}).map(([key, items]) =>
                                  Array.isArray(items) && items.length > 0 ? (
                                    <div key={key} className="flex items-start gap-3">
                                      <span className="text-[10px] font-mono w-24 flex-shrink-0 pt-0.5" style={{ color: mutedText }}>
                                        {key.replace(/([A-Z])/g, ' $1').toLowerCase().trim()}
                                      </span>
                                      <div className="flex flex-wrap gap-1">
                                        {items.map(item => (
                                          <span
                                            key={item}
                                            className="px-2 py-0.5 text-[10px] font-mono"
                                            style={{ background: pageBg, border: `1px solid ${borderColor}`, borderLeft: '2px solid #3b82f6', borderRadius: 3, color: bodyText }}
                                          >
                                            {item}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  ) : null
                                )}
                              </div>
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                )
              })}
            </AnimatePresence>
          </div>
        )}
      </div>
    </div>
  )
}
