import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion } from 'framer-motion'
import { ArrowUpRight, RefreshCw } from 'lucide-react'
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, LabelList,
} from 'recharts'
import { fetchSessions, fetchStats } from '../lib/api'
import { TYPE_LABELS, SCAM_COLORS } from '../lib/labels'

const INTEL_ROWS = [
  { key: 'suspiciousKeywords', label: 'Keywords' },
  { key: 'phoneNumbers',       label: 'Phone numbers' },
  { key: 'upiIds',             label: 'UPI IDs' },
  { key: 'bankAccounts',       label: 'Bank accounts' },
  { key: 'phishingLinks',      label: 'Phishing links' },
  { key: 'emailAddresses',     label: 'Emails' },
]

const ACCENT = '#C2410C'

function palette() {
  return {
    bg:       'transparent',
    surface:  '#FFFFFF',
    surface2: '#F3F4F6',
    line:     'rgba(0,0,0,0.07)',
    lineSoft: 'rgba(0,0,0,0.04)',
    text:     '#0D0D0D',
    muted:    '#6B7280',
    faint:    '#B0A99E',
  }
}

// ── Count-up animation for headline / KPI numbers ──
function useCountUp(target, duration = 1100) {
  const [value, setValue] = useState(0)
  useEffect(() => {
    if (typeof target !== 'number' || Number.isNaN(target)) { setValue(0); return }
    let raf
    let start = null
    const step = (ts) => {
      if (start === null) start = ts
      const p = Math.min((ts - start) / duration, 1)
      const eased = 1 - Math.pow(1 - p, 3) // easeOutCubic
      setValue(target * eased)
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return value
}

function CountUp({ value, decimals = 0, style, className }) {
  const v = useCountUp(typeof value === 'number' ? value : 0)
  const display = v.toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  })
  return <span className={className} style={style}>{display}</span>
}

// ── Thin magnitude bar row — identity from the label, mono for numbers only ──
function BarRow({ label, count, max, C, color = ACCENT, swatch = false }) {
  const zero = count === 0
  const pct = max > 0 ? Math.max((count / max) * 100, 1.5) : 0
  return (
    <div className="flex items-center gap-3" style={{ marginTop: 13 }}>
      <span className="text-xs truncate flex items-center gap-1.5" style={{ color: zero ? C.faint : C.muted, width: 128, flexShrink: 0 }}>
        {swatch && (
          <span style={{ width: 6, height: 6, borderRadius: 1, background: zero ? C.faint : color, flexShrink: 0 }} />
        )}
        {label}
      </span>
      <div className="flex-1" style={{ height: 6, borderRadius: 2, background: C.surface2, overflow: 'hidden' }}>
        {!zero && (
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            style={{ height: '100%', borderRadius: 2, background: color }}
          />
        )}
      </div>
      <span className="text-xs font-mono font-bold text-right" style={{ color: zero ? C.faint : C.text, width: 40, flexShrink: 0 }}>
        {count.toLocaleString()}
      </span>
    </div>
  )
}

function Card({ title, meta, children, C, className = '' }) {
  return (
    <div
      className={`glass-card ${className}`}
      style={{ padding: '20px 22px 22px' }}
    >
      <div style={{
        display: 'flex', alignItems: 'baseline', justifyContent: 'space-between',
        marginBottom: 14, paddingBottom: 12,
        borderBottom: '1px solid rgba(0,0,0,0.05)',
      }}>
        <p style={{ fontSize: 12.5, fontWeight: 700, color: C.text, letterSpacing: '-0.01em' }}>{title}</p>
        {meta && <p style={{ fontSize: 10, color: C.faint }}>{meta}</p>}
      </div>
      {children}
    </div>
  )
}

// Direct label on the tallest bar only
function maxOnlyLabel(maxValue, color) {
  return function MaxLabel({ x, y, width, value }) {
    if (value !== maxValue || !value) return null
    return (
      <text x={x + width / 2} y={y - 6} textAnchor="middle"
            style={{ fontFamily: 'ui-monospace, Consolas, monospace', fontSize: 10, fontWeight: 700, fill: color }}>
        {value}
      </text>
    )
  }
}

export default function OverviewPage() {
  const C = palette()
  const [sessions, setSessions] = useState([])
  const [serverStats, setServerStats] = useState(null)
  const [loading, setLoading]   = useState(true)
  const [fetchError, setFetchError] = useState(null)

  const load = useCallback(async () => {
    setFetchError(null)
    try {
      const [data, stats] = await Promise.all([fetchSessions(100), fetchStats()])
      setSessions(data)
      setServerStats(stats)
    } catch (err) {
      const status = err?.response?.status
      setFetchError(status === 401 ? 'Admin session expired — log in again' : `Backend unreachable: ${err?.message || 'unknown'}`)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, 30000)
    return () => clearInterval(interval)
  }, [load])

  // ── Aggregates ──────────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const intelTotal = sessions.reduce((sum, s) =>
      sum + Object.values(s.intelligence || {}).filter(Array.isArray).flat().length, 0)
    const turns = sessions.map(s => s.turnCount || 0)
    const avgTurns = turns.length ? (turns.reduce((a, b) => a + b, 0) / turns.length) : 0
    const repeats = sessions.filter(s => s.repeatScammer).length
    return { total: sessions.length, intelTotal, avgTurns: avgTurns.toFixed(1), repeats }
  }, [sessions])

  const typeBars = useMemo(() => {
    const counts = {}
    sessions.forEach(s => {
      const key = s.scamType || 'unknown'
      counts[key] = (counts[key] || 0) + 1
    })
    return Object.entries(counts)
      .map(([key, count]) => ({
        key,
        label: TYPE_LABELS[key] || key.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase()),
        count,
      }))
      .sort((a, b) => b.count - a.count)
  }, [sessions])

  const intelBars = useMemo(() => (
    INTEL_ROWS.map(({ key, label }) => ({
      key,
      label,
      count: sessions.reduce((sum, s) => sum + ((s.intelligence?.[key] || []).length), 0),
    })).sort((a, b) => b.count - a.count)
  ), [sessions])

  // ML detection score histogram (real model output)
  const scoreData = useMemo(() => {
    const buckets = [
      { name: '0–.2',  from: 0.0, to: 0.2, count: 0 },
      { name: '.2–.4', from: 0.2, to: 0.4, count: 0 },
      { name: '.4–.6', from: 0.4, to: 0.6, count: 0 },
      { name: '.6–.8', from: 0.6, to: 0.8, count: 0 },
      { name: '.8–1',  from: 0.8, to: 1.01, count: 0 },
    ]
    let unscored = 0
    sessions.forEach(s => {
      const score = typeof s.mlScore === 'number' ? s.mlScore
        : (typeof s.ruleScore === 'number' ? s.ruleScore : null)
      if (score === null) { unscored += 1; return }
      const b = buckets.find(b => score >= b.from && score < b.to)
      if (b) b.count += 1
    })
    return { buckets, unscored, scored: sessions.length - unscored }
  }, [sessions])

  // Active days only — bars, not a line, so date gaps can't fake continuity
  const timeline = useMemo(() => {
    const byDay = {}
    sessions.forEach(s => {
      const ts = s.startTime || s.savedAt
      if (!ts) return
      const day = new Date(ts).toISOString().slice(0, 10)
      byDay[day] = (byDay[day] || 0) + 1
    })
    const days = Object.entries(byDay).sort(([a], [b]) => a.localeCompare(b))
    let hasGap = false
    for (let i = 1; i < days.length; i++) {
      const prev = new Date(days[i - 1][0])
      const cur  = new Date(days[i][0])
      if ((cur - prev) / 86400000 > 1) { hasGap = true; break }
    }
    return {
      data: days.map(([day, count]) => ({
        day: new Date(day).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }),
        count,
      })),
      hasGap,
    }
  }, [sessions])

  const maxType  = Math.max(0, ...typeBars.map(t => t.count))
  const maxIntel = Math.max(0, ...intelBars.map(t => t.count))
  const maxScore = Math.max(0, ...scoreData.buckets.map(b => b.count))
  const maxDay   = Math.max(0, ...timeline.data.map(d => d.count))

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null
    return (
      <div className="px-3 py-2 text-xs font-mono" style={{ background: C.bg, border: `1px solid ${C.line}`, borderRadius: 4 }}>
        <p className="font-semibold mb-1" style={{ color: C.text }}>{label}</p>
        {payload.map(p => (
          <p key={p.name} style={{ color: C.muted }}>{p.name}: {p.value}</p>
        ))}
      </div>
    )
  }

  const axisTick = { fontSize: 10, fill: C.faint, fontFamily: 'ui-monospace, Consolas, monospace' }

  const tiles = [
    { label: 'Sessions captured',       value: stats.total,               decimals: 0 },
    { label: 'Intel items extracted',   value: stats.intelTotal,          decimals: 0 },
    { label: 'Avg turns per session',   value: parseFloat(stats.avgTurns), decimals: 1 },
    { label: 'Repeat scammers flagged', value: stats.repeats,             decimals: 0 },
  ]

  return (
    <div className="h-full overflow-y-auto" style={{ background: 'transparent' }}>
      <div className="mx-auto px-5 sm:px-10" style={{ maxWidth: 1060, paddingTop: 32, paddingBottom: 48 }}>

        {/* ── Header owns the page title AND the demo CTA — no banner box ── */}
        <header className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 sm:gap-6">
          <div>
            <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', color: C.text, lineHeight: 1.1 }}>Overview</h1>
            <p className="mt-1.5" style={{ fontSize: 12.5, color: C.muted, maxWidth: '52ch', lineHeight: 1.55 }}>
              Evidence from <b style={{ color: C.text, fontWeight: 600 }}>
              {loading ? '…' : `${stats.total} autonomous sessions`}</b> — detection, persona
              engagement, and intelligence extraction, all without human input.
            </p>
          </div>
          <div className="flex-shrink-0">
            <a
              href="/demo.html"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 font-bold"
              style={{ background: ACCENT, color: '#ffffff', borderRadius: 4, fontSize: 13, padding: '11px 18px', textDecoration: 'none' }}
            >
              Open Phone Demo
              <ArrowUpRight size={14} />
            </a>
            <p className="text-right mt-1.5" style={{ fontSize: 10.5, color: C.faint }}>
              live honeypot vs. AI scammer, in real time
            </p>
          </div>
        </header>

        {/* ── Error state ── */}
        {fetchError && (
          <div className="mt-6 text-xs font-mono" style={{ border: `1px solid ${C.line}`, borderRadius: 6, padding: 20, color: C.muted }}>
            <p style={{ color: '#ef4444' }}>{fetchError}</p>
            <p className="mt-1">Stats need the backend + MongoDB. The phone demo still works if the backend is running.</p>
          </div>
        )}

        {/* ── Lead stat strip, four figures, hairline dividers ── */}
        <div className="glass-card grid grid-cols-2 sm:grid-cols-4 mt-6">
          {tiles.map((t, i) => (
            <div key={t.label} style={{ padding: '30px 26px', borderLeft: i > 0 ? `1px solid ${C.lineSoft}` : 'none' }}>
              <p className="font-mono font-bold" style={{ fontSize: 40, letterSpacing: '-0.02em', color: C.text, lineHeight: 1 }}>
                {loading ? '—' : <CountUp value={t.value} decimals={t.decimals} />}
              </p>
              <p style={{ marginTop: 10, fontSize: 12, fontWeight: 600, color: C.muted }}>{t.label}</p>
            </div>
          ))}
        </div>

        {/* ── Scammer time-waste meter (server-aggregated) ── */}
        <div className="glass-card grid grid-cols-1 sm:grid-cols-2 mt-4">
          {[
            { label: 'Scammer time wasted', value: serverStats?.scammerTimeWastedHuman ?? '—', hint: 'total engagement across all sessions' },
            { label: 'Avg time per scammer', value: serverStats?.avgEngagementHuman ?? '—', hint: 'mean session duration' },
          ].map((t, i) => (
            <div key={t.label} style={{ padding: '18px 24px', borderLeft: i > 0 ? `1px solid ${C.lineSoft}` : 'none' }}>
              <p className="font-mono font-bold" style={{ fontSize: 22, letterSpacing: '-0.01em', color: ACCENT, lineHeight: 1.1 }}>
                {loading ? '—' : t.value}
              </p>
              <p className="mt-1.5" style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{t.label}</p>
              <p style={{ fontSize: 10, color: C.faint, marginTop: 2 }}>{t.hint}</p>
            </div>
          ))}
        </div>

        {/* ── Breakdown rows ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <Card title="Scam types encountered" meta={`${stats.total} sessions`} C={C}>
            {typeBars.length === 0 && <p className="text-xs mt-3" style={{ color: C.faint }}>No sessions yet</p>}
            {typeBars.map(t => (
              <BarRow key={t.key} label={t.label} count={t.count} max={maxType} C={C}
                      color={SCAM_COLORS[t.key] || ACCENT} swatch />
            ))}
          </Card>

          <Card title="Intelligence extracted" meta={`${stats.intelTotal.toLocaleString()} items · ${INTEL_ROWS.length} categories`} C={C}>
            {intelBars.map(t => (
              <BarRow key={t.key} label={t.label} count={t.count} max={maxIntel} C={C} />
            ))}
          </Card>
        </div>

        {/* ── Charts ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <Card title="Detection score distribution" meta={`DistilBERT confidence · ${scoreData.scored} scored${scoreData.unscored ? ` · ${scoreData.unscored} pre-ML` : ''}`} C={C}>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={scoreData.buckets} barSize={40} margin={{ top: 16, right: 0, left: -32, bottom: 0 }}>
                <CartesianGrid stroke={C.lineSoft} vertical={false} strokeDasharray="" />
                <XAxis dataKey="name" tick={axisTick} axisLine={{ stroke: C.line }} tickLine={false} />
                <YAxis allowDecimals={false} tick={false} axisLine={false} width={32} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
                <Bar dataKey="count" name="Sessions" fill={ACCENT} radius={[2, 2, 0, 0]}>
                  <LabelList content={maxOnlyLabel(maxScore, C.text)} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <p className="mt-3" style={{ fontSize: 10.5, color: C.faint, lineHeight: 1.5 }}>
              Classifier confidence per session — training-time eval lives below; no live accuracy is claimed.
            </p>
          </Card>

          <Card title="Sessions by day" meta={`${timeline.data.length} active days`} C={C}>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={timeline.data} barSize={32} margin={{ top: 16, right: 0, left: -32, bottom: 0 }}>
                <CartesianGrid stroke={C.lineSoft} vertical={false} strokeDasharray="" />
                <XAxis dataKey="day" tick={axisTick} axisLine={{ stroke: C.line }} tickLine={false} interval="preserveStartEnd" />
                <YAxis allowDecimals={false} tick={false} axisLine={false} width={32} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
                <Bar dataKey="count" name="Sessions" fill={ACCENT} radius={[2, 2, 0, 0]}>
                  <LabelList content={maxOnlyLabel(maxDay, C.text)} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            {timeline.hasGap && (
              <p className="mt-3" style={{ fontSize: 10.5, color: C.faint, lineHeight: 1.5 }}>
                Only active days shown — inactive gaps between dates are compressed.
              </p>
            )}
          </Card>
        </div>

        {/* ── Models: one quiet strip ── */}
        <div className="glass-card grid grid-cols-1 md:grid-cols-2 mt-4">
          <div style={{ padding: '18px 24px' }}>
            <p style={{ fontSize: 12.5, fontWeight: 700, color: C.text }}>
              DistilBERT, fine-tuned
              <span style={{ color: ACCENT, fontWeight: 600, fontSize: 10.5, marginLeft: 8 }}>PRIMARY</span>
            </p>
            <p className="mt-1" style={{ fontSize: 11.5, color: C.muted, lineHeight: 1.5 }}>
              100% on the held-out test split · 164,670 samples · runs locally, classifies every first message.
            </p>
          </div>
          <div style={{ padding: '18px 24px', borderLeft: `1px solid ${C.lineSoft}` }}>
            <p style={{ fontSize: 12.5, fontWeight: 700, color: C.text }}>
              TF-IDF + Logistic Regression
              <span style={{ color: C.muted, fontWeight: 600, fontSize: 10.5, marginLeft: 8 }}>FALLBACK</span>
            </p>
            <p className="mt-1" style={{ fontSize: 11.5, color: C.muted, lineHeight: 1.5 }}>
              75.7% test accuracy · &lt;1MB, ships in the repo — detection works on any fresh clone.
            </p>
          </div>
          <div className="col-span-2" style={{ borderTop: `1px solid ${C.lineSoft}`, padding: '10px 24px', fontSize: 10.5, color: C.faint }}>
            Offline training evaluation on labeled data. Live sessions have no ground truth, so no live accuracy is claimed.
          </div>
        </div>

        <div className="flex items-center gap-1.5 mt-4">
          <RefreshCw size={10} style={{ color: C.faint }} />
          <span style={{ fontSize: 10.5, color: C.faint }}>Auto-refreshes every 30s from MongoDB</span>
        </div>
      </div>
    </div>
  )
}
