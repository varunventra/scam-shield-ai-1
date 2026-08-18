import { Shield, LayoutDashboard, Search, FileText, ArrowUpRight } from 'lucide-react'

const NAV = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: Search },
  { id: 'reports',  label: 'Reports',  icon: FileText },
]

const BG       = '#FDFCFA'
const BORDER   = '#E2DBD3'
const BODY     = '#1C1714'
const MUTED    = '#7A6F67'
const ACCENT   = '#3b82f6'

export default function Sidebar({ page, onPageChange }) {
  return (
    <div
      className="w-56 flex flex-col py-6 px-4 flex-shrink-0"
      style={{
        background: `linear-gradient(180deg, #FFFFFF 0%, ${BG} 100%)`,
        borderRight: `1px solid ${BORDER}`,
        boxShadow: '2px 0 12px rgba(100,80,60,0.06)',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-2 mb-6">
        <div
          className="w-8 h-8 flex items-center justify-center"
          style={{
            background: 'linear-gradient(135deg, #3b82f6 0%, #6366f1 100%)',
            borderRadius: 6,
            boxShadow: '0 2px 8px rgba(59,130,246,0.30)',
          }}
        >
          <Shield size={15} color="#ffffff" />
        </div>
        <div>
          <p style={{ fontWeight: 700, fontSize: 15, color: BODY, lineHeight: 1.2 }}>ScamShield</p>
          <p style={{ fontSize: 10, color: MUTED }}>Honeypot AI</p>
        </div>
      </div>

      {/* Section label */}
      <p style={{ fontSize: 9.5, fontWeight: 700, color: MUTED, letterSpacing: '0.08em', paddingLeft: 12, marginBottom: 4 }}>
        CONSOLE
      </p>

      {/* Page nav */}
      <nav className="space-y-0.5 mb-6">
        {NAV.map(({ id, label, icon: Icon }) => {
          const isActive = page === id
          return (
            <button
              key={id}
              onClick={() => onPageChange(id)}
              aria-current={isActive ? 'page' : undefined}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 text-sm font-medium transition-all"
              style={{
                color:        isActive ? ACCENT : MUTED,
                borderLeft:   isActive ? `2px solid ${ACCENT}` : '2px solid transparent',
                borderRadius: isActive ? '0 6px 6px 0' : 0,
                background:   isActive
                  ? 'linear-gradient(90deg, rgba(59,130,246,0.08) 0%, transparent 100%)'
                  : 'transparent',
              }}
            >
              <Icon size={15} aria-hidden="true" />
              <span className="flex-1 text-left">{label}</span>
            </button>
          )
        })}
      </nav>

      {/* Divider */}
      <div style={{ height: 1, background: BORDER, marginBottom: 12 }} />

      {/* Live demo link */}
      <a
        href="/demo.html"
        target="_blank"
        rel="noopener noreferrer"
        className="flex items-center gap-2.5 px-3 py-2.5 text-sm font-semibold w-full transition-all"
        style={{
          color:          BODY,
          border:         `1px solid ${BORDER}`,
          borderRadius:   8,
          textDecoration: 'none',
          background:     'linear-gradient(135deg, #FFFFFF 0%, #F7F3EE 100%)',
          boxShadow:      '0 1px 4px rgba(100,80,60,0.07), inset 0 1px 0 rgba(255,255,255,0.9)',
        }}
        onMouseEnter={e => { e.currentTarget.style.borderColor = ACCENT; e.currentTarget.style.boxShadow = '0 2px 10px rgba(59,130,246,0.15), inset 0 1px 0 rgba(255,255,255,0.9)' }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = BORDER; e.currentTarget.style.boxShadow = '0 1px 4px rgba(100,80,60,0.07), inset 0 1px 0 rgba(255,255,255,0.9)' }}
      >
        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: '#22c55e', boxShadow: '0 0 6px #22c55e' }} />
        <span className="flex-1 text-left">Phone Demo</span>
        <ArrowUpRight size={13} style={{ color: MUTED }} />
      </a>

      <div className="flex-1" />

      {/* Footer identity */}
      <div
        className="mt-3 pt-3 flex items-center gap-2.5 px-1"
        style={{ borderTop: `1px solid ${BORDER}` }}
      >
        <div
          className="w-8 h-8 flex items-center justify-center text-xs font-mono font-bold flex-shrink-0"
          style={{
            background:   'linear-gradient(135deg, #F7F3EE 0%, #EDE8E0 100%)',
            border:       `1px solid ${BORDER}`,
            borderRadius: 6,
            color:        BODY,
            boxShadow:    'inset 0 1px 0 rgba(255,255,255,0.8)',
          }}
        >
          S
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-mono font-semibold truncate" style={{ color: BODY }}>CONSOLE</p>
          <p className="text-[10px] truncate" style={{ color: MUTED }}>ScamShield AI</p>
        </div>
      </div>
    </div>
  )
}
