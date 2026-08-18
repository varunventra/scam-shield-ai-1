import { Shield, LayoutDashboard, Search, FileText, Moon, Sun, LogOut, ArrowUpRight } from 'lucide-react'
import { useEffect, useState } from 'react'
import { toggleDark, initDark } from '../hooks/darkMode'

const NAV = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: Search },
  { id: 'reports',  label: 'Reports',  icon: FileText },
]

export default function Sidebar({ page, onPageChange, onExit }) {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))

  const handleToggleDark = () => {
    const next = toggleDark()
    setDark(next)
  }

  useEffect(() => {
    initDark()
    setDark(document.documentElement.classList.contains('dark'))
  }, [])

  const borderColor  = dark ? '#27272a' : '#e4e4e7'
  const pageBg       = dark ? '#09090b' : '#ffffff'
  const bodyText     = dark ? '#fafafa'  : '#111111'
  const mutedText    = '#71717a'

  return (
    <div
      className="w-56 flex flex-col py-6 px-4 flex-shrink-0 transition-colors"
      style={{ background: pageBg, borderRight: `1px solid ${borderColor}` }}
    >

      {/* Logo */}
      <div className="flex items-center gap-2.5 px-2 mb-6">
        <div className="w-8 h-8 flex items-center justify-center" style={{ border: `1px solid ${borderColor}`, borderRadius: 4 }}>
          <Shield size={15} style={{ color: bodyText }} />
        </div>
        <div>
          <p style={{ fontWeight: 800, fontSize: 15, color: bodyText, lineHeight: 1.2 }}>ScamShield</p>
          <p style={{ fontSize: 10, color: mutedText }}>Honeypot AI</p>
        </div>
      </div>

      {/* Page nav */}
      <nav className="space-y-0.5 mb-6">
        {NAV.map(({ id, label, icon: Icon }) => {
          const isActive = page === id
          return (
            <button
              key={id}
              onClick={() => onPageChange(id)}
              aria-current={isActive ? 'page' : undefined}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 text-sm font-medium transition-colors"
              style={{
                color: isActive ? '#3b82f6' : mutedText,
                borderLeft: isActive ? '2px solid #3b82f6' : '2px solid transparent',
                borderRadius: 0,
                background: 'transparent',
              }}
            >
              <Icon size={15} aria-hidden="true" />
              <span className="flex-1 text-left">{label}</span>
            </button>
          )
        })}
      </nav>

      {/* Live demo — the way to actually test the honeypot */}
      <a
        href="/demo.html"
        target="_blank"
        rel="noopener noreferrer"
        className="flex items-center gap-2.5 px-3 py-2.5 text-sm font-semibold w-full mt-4"
        style={{
          color: bodyText,
          border: `1px solid ${borderColor}`,
          borderRadius: 4,
          textDecoration: 'none',
        }}
        onMouseEnter={e => e.currentTarget.style.borderColor = '#3b82f6'}
        onMouseLeave={e => e.currentTarget.style.borderColor = borderColor}
      >
        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: '#22c55e' }} />
        <span className="flex-1 text-left">Phone Demo</span>
        <ArrowUpRight size={13} style={{ color: mutedText }} />
      </a>

      <div className="flex-1" />

      {/* Dark mode toggle */}
      <button
        onClick={handleToggleDark}
        className="flex items-center gap-2 px-3 py-2.5 text-sm transition-colors w-full mb-1"
        style={{ color: mutedText, borderRadius: 4, background: 'transparent' }}
        onMouseEnter={e => e.currentTarget.style.color = bodyText}
        onMouseLeave={e => e.currentTarget.style.color = mutedText}
      >
        {dark ? <Sun size={14} /> : <Moon size={14} />}
        {dark ? 'Light mode' : 'Dark mode'}
      </button>

      {/* Console identity + back to landing */}
      <div className="mt-3 pt-3 flex items-center gap-2.5 px-1" style={{ borderTop: `1px solid ${borderColor}` }}>
        <div
          className="w-8 h-8 flex items-center justify-center text-xs font-mono font-bold flex-shrink-0"
          style={{ border: `1px solid ${borderColor}`, borderRadius: 4, color: bodyText, background: pageBg }}
        >
          S
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-mono font-semibold truncate" style={{ color: bodyText }}>CONSOLE</p>
          <p className="text-[10px] truncate" style={{ color: mutedText }}>ScamShield AI</p>
        </div>
        {onExit && (
          <button
            onClick={onExit}
            title="Back to landing page"
            aria-label="Back to landing page"
            className="flex-shrink-0 p-1.5 transition-colors"
            style={{ color: mutedText, borderRadius: 4 }}
            onMouseEnter={e => e.currentTarget.style.color = bodyText}
            onMouseLeave={e => e.currentTarget.style.color = mutedText}
          >
            <LogOut size={13} aria-hidden="true" />
          </button>
        )}
      </div>
    </div>
  )
}
