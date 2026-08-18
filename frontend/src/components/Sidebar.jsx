import { Shield, LayoutDashboard, Search, FileText, ArrowUpRight, Radio } from 'lucide-react'

const NAV = [
  { id: 'overview', label: 'Overview',  icon: LayoutDashboard },
  { id: 'findings', label: 'Findings',  icon: Search },
  { id: 'reports',  label: 'Reports',   icon: FileText },
]

export default function Sidebar({ page, onPageChange }) {
  return (
    <aside
      style={{
        width: 220,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        padding: '20px 12px',
        background: '#FFFFFF',
        borderRight: '1px solid rgba(0,0,0,0.07)',
        boxShadow: '2px 0 12px rgba(0,0,0,0.04)',
      }}
    >
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 8px', marginBottom: 28 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, flexShrink: 0,
          background: 'linear-gradient(135deg, #2563EB 0%, #7C3AED 100%)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 2px 8px rgba(37,99,235,0.35)',
        }}>
          <Shield size={16} color="#fff" />
        </div>
        <div>
          <p style={{ fontSize: 14, fontWeight: 700, color: '#0D0D0D', lineHeight: 1.2 }}>ScamShield</p>
          <p style={{ fontSize: 10, color: '#9CA3AF', letterSpacing: '0.03em' }}>Honeypot AI</p>
        </div>
      </div>

      {/* Nav label */}
      <p style={{ fontSize: 9.5, fontWeight: 700, color: '#B0A99E', letterSpacing: '0.1em', padding: '0 10px', marginBottom: 6 }}>
        MENU
      </p>

      {/* Nav */}
      <nav style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {NAV.map(({ id, label, icon: Icon }) => {
          const active = page === id
          return (
            <button
              key={id}
              onClick={() => onPageChange(id)}
              aria-current={active ? 'page' : undefined}
              style={{
                display: 'flex', alignItems: 'center', gap: 9,
                padding: '8px 10px',
                borderRadius: 8,
                border: 'none',
                cursor: 'pointer',
                fontSize: 13.5,
                fontWeight: active ? 600 : 500,
                color: active ? '#2563EB' : '#6B7280',
                background: active ? 'rgba(37,99,235,0.07)' : 'transparent',
                transition: 'all 0.15s',
                textAlign: 'left',
                width: '100%',
              }}
              onMouseEnter={e => { if (!active) { e.currentTarget.style.background = 'rgba(0,0,0,0.04)'; e.currentTarget.style.color = '#0D0D0D' } }}
              onMouseLeave={e => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#6B7280' } }}
            >
              <Icon size={15} />
              <span>{label}</span>
              {active && <span style={{ marginLeft: 'auto', width: 5, height: 5, borderRadius: '50%', background: '#2563EB' }} />}
            </button>
          )
        })}
      </nav>

      <div style={{ flex: 1 }} />

      {/* Divider */}
      <div style={{ height: 1, background: 'rgba(0,0,0,0.06)', margin: '16px 4px' }} />

      {/* Phone Demo */}
      <a
        href="/demo.html"
        target="_blank"
        rel="noopener noreferrer"
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '9px 12px',
          borderRadius: 8,
          border: '1px solid rgba(0,0,0,0.09)',
          background: 'linear-gradient(135deg, #FAFAFA 0%, #F3F3F3 100%)',
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.9), 0 1px 3px rgba(0,0,0,0.05)',
          textDecoration: 'none',
          color: '#0D0D0D',
          fontSize: 13,
          fontWeight: 600,
          transition: 'box-shadow 0.15s',
          marginBottom: 16,
        }}
        onMouseEnter={e => { e.currentTarget.style.boxShadow = 'inset 0 1px 0 rgba(255,255,255,0.9), 0 2px 10px rgba(37,99,235,0.14)'; e.currentTarget.style.borderColor = 'rgba(37,99,235,0.3)' }}
        onMouseLeave={e => { e.currentTarget.style.boxShadow = 'inset 0 1px 0 rgba(255,255,255,0.9), 0 1px 3px rgba(0,0,0,0.05)'; e.currentTarget.style.borderColor = 'rgba(0,0,0,0.09)' }}
      >
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#16A34A', boxShadow: '0 0 6px rgba(22,163,74,0.6)', flexShrink: 0 }} />
        <span style={{ flex: 1 }}>Phone Demo</span>
        <ArrowUpRight size={13} color="#9CA3AF" />
      </a>

      {/* Footer */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 4px' }}>
        <div style={{
          width: 30, height: 30, borderRadius: 6, flexShrink: 0,
          background: 'linear-gradient(135deg, #F3F4F6 0%, #E5E7EB 100%)',
          border: '1px solid rgba(0,0,0,0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 11, fontWeight: 700, color: '#374151',
        }}>S</div>
        <div style={{ minWidth: 0 }}>
          <p style={{ fontSize: 11.5, fontWeight: 600, color: '#0D0D0D', lineHeight: 1.2 }}>Console</p>
          <p style={{ fontSize: 10, color: '#9CA3AF' }}>ScamShield AI</p>
        </div>
      </div>
    </aside>
  )
}
