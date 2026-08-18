import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { Shield, ArrowRight, Smartphone, Sun, Moon } from 'lucide-react'
import { useDarkMode } from '../hooks/useDarkMode'
import { toggleDark } from '../hooks/darkMode'

// ── Stat counter ─────────────────────────────────────────────────────────────
function useCountUp(target, duration = 1200) {
  const [value, setValue] = useState(0)
  useEffect(() => {
    let start = null
    const step = (ts) => {
      if (!start) start = ts
      const progress = Math.min((ts - start) / duration, 1)
      setValue(Math.floor(progress * target))
      if (progress < 1) requestAnimationFrame(step)
    }
    const raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return value
}

// ── Terminal typewriter ───────────────────────────────────────────────────────
const LOG_LINES = [
  { prefix: '[INTERCEPT]', text: '  Bank fraud · grandmother · +91 98XXX XXXXX extracted' },
  { prefix: '[INTERCEPT]', text: '  KYC scam · professional · UPI ID extracted' },
  { prefix: '[DETECT]',    text: '     Phishing · college student · 2 links flagged' },
]

function TerminalLog() {
  const [lineIndex, setLineIndex]   = useState(0)
  const [charIndex, setCharIndex]   = useState(0)
  const [displayed, setDisplayed]   = useState([])   // completed lines
  const [cursorOn, setCursorOn]     = useState(true)
  const timerRef  = useRef(null)
  const cursorRef = useRef(null)

  useEffect(() => {
    // Cursor blink — 530ms interval, independent of typing
    cursorRef.current = setInterval(() => setCursorOn(v => !v), 530)
    return () => clearInterval(cursorRef.current)
  }, [])

  useEffect(() => {
    const fullLine   = LOG_LINES[lineIndex]
    const fullString = fullLine.prefix + fullLine.text

    if (charIndex < fullString.length) {
      // Still typing current line
      timerRef.current = setTimeout(() => setCharIndex(c => c + 1), 35)
    } else {
      // Line complete — pause 800ms then move to next line
      timerRef.current = setTimeout(() => {
        const nextIndex = (lineIndex + 1) % LOG_LINES.length
        if (nextIndex === 0) {
          // All lines done — clear and restart
          setDisplayed([])
        } else {
          setDisplayed(prev => [...prev, { ...fullLine, fullString }])
        }
        setLineIndex(nextIndex)
        setCharIndex(0)
      }, 800)
    }

    return () => clearTimeout(timerRef.current)
  }, [lineIndex, charIndex])

  const currentFull   = LOG_LINES[lineIndex].prefix + LOG_LINES[lineIndex].text
  const currentTyped  = currentFull.slice(0, charIndex)
  const prefixLen     = LOG_LINES[lineIndex].prefix.length
  const typedPrefix   = currentTyped.slice(0, Math.min(charIndex, prefixLen))
  const typedRest     = currentTyped.slice(prefixLen)

  return (
    <div
      style={{
        background: '#060d1a',
        borderLeft: '2px solid #3b82f6',
        padding: '14px 16px',
        minHeight: 88,
      }}
    >
      {/* Completed lines */}
      {displayed.map((line, i) => (
        <div key={i} style={{ fontFamily: 'monospace', fontSize: 11, lineHeight: '22px', color: '#94a3b8', whiteSpace: 'nowrap' }}>
          <span style={{ color: '#3b82f6' }}>{line.prefix}</span>
          {line.text}
        </div>
      ))}

      {/* Currently typing line */}
      <div style={{ fontFamily: 'monospace', fontSize: 11, lineHeight: '22px', color: '#94a3b8', whiteSpace: 'nowrap' }}>
        <span style={{ color: '#3b82f6' }}>{typedPrefix}</span>
        {typedRest}
        {/* Blinking cursor */}
        <span style={{ opacity: cursorOn ? 1 : 0, color: '#3b82f6', fontWeight: 700 }}>|</span>
      </div>
    </div>
  )
}

// ── Radar pulse rings ─────────────────────────────────────────────────────────
const RING_DELAYS = [0, 0.8, 1.6]   // seconds stagger

function RadarRings() {
  return (
    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none', zIndex: 0 }}>
      {RING_DELAYS.map((delay, i) => (
        <motion.div
          key={i}
          style={{
            position: 'absolute',
            width: 56,
            height: 56,
            borderRadius: '50%',
            border: '1px solid rgba(59,130,246,0.15)',
          }}
          animate={{
            scale: [1, 2.5],
            opacity: [0.4, 0],
          }}
          transition={{
            duration: 2.4,
            delay,
            repeat: Infinity,
            ease: 'easeOut',
            repeatDelay: 0,
          }}
        />
      ))}
    </div>
  )
}

// ── Dot grid background ───────────────────────────────────────────────────────
function DotGrid() {
  return (
    <svg
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <pattern id="dot-grid" x="0" y="0" width="28" height="28" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="1" fill="rgba(59,130,246,0.18)" />
        </pattern>
        <radialGradient id="dot-fade" cx="50%" cy="50%" r="55%">
          <stop offset="0%" stopColor="white" stopOpacity="0" />
          <stop offset="60%" stopColor="white" stopOpacity="0" />
          <stop offset="100%" stopColor="black" stopOpacity="1" />
        </radialGradient>
        <mask id="dot-mask">
          <rect width="100%" height="100%" fill="white" />
          <rect width="100%" height="100%" fill="url(#dot-fade)" />
        </mask>
      </defs>
      <rect width="100%" height="100%" fill="url(#dot-grid)" mask="url(#dot-mask)" />
    </svg>
  )
}

// ── Scan line ─────────────────────────────────────────────────────────────────
function ScanLine() {
  return (
    <motion.div
      style={{
        position: 'absolute',
        left: 0,
        right: 0,
        height: 1,
        background: 'linear-gradient(90deg, transparent 0%, rgba(59,130,246,0.0) 15%, rgba(59,130,246,0.35) 50%, rgba(59,130,246,0.0) 85%, transparent 100%)',
        pointerEvents: 'none',
        zIndex: 1,
      }}
      animate={{ top: ['0%', '100%'] }}
      transition={{ duration: 5, repeat: Infinity, ease: 'linear', repeatDelay: 1.5 }}
    />
  )
}

// ── Floating data nodes ───────────────────────────────────────────────────────
const DATA_NODES = [
  { x: '12%', y: '18%', label: 'UPI', delay: 0 },
  { x: '78%', y: '12%', label: 'OTP', delay: 0.6 },
  { x: '88%', y: '55%', label: 'KYC', delay: 1.1 },
  { x: '8%',  y: '72%', label: 'NER', delay: 0.3 },
  { x: '55%', y: '88%', label: 'ML',  delay: 0.9 },
  { x: '68%', y: '30%', label: 'IP',  delay: 1.5 },
]

function DataNodes() {
  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 1 }}>
      {DATA_NODES.map((node, i) => (
        <motion.div
          key={i}
          style={{
            position: 'absolute',
            left: node.x,
            top: node.y,
            display: 'flex',
            alignItems: 'center',
            gap: 5,
          }}
          initial={{ opacity: 0, scale: 0.6 }}
          animate={{ opacity: [0, 0.55, 0.55, 0], scale: [0.6, 1, 1, 0.6] }}
          transition={{
            duration: 4,
            delay: node.delay + 0.8,
            repeat: Infinity,
            repeatDelay: 3,
            ease: 'easeInOut',
          }}
        >
          <div style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: 'rgba(59,130,246,0.7)',
            boxShadow: '0 0 6px rgba(59,130,246,0.5)',
          }} />
          <span style={{
            fontFamily: 'monospace',
            fontSize: 9,
            color: 'rgba(59,130,246,0.55)',
            letterSpacing: '0.1em',
          }}>{node.label}</span>
        </motion.div>
      ))}
    </div>
  )
}

// ── Hex grid overlay ──────────────────────────────────────────────────────────
function HexGrid() {
  // A small SVG hex tile repeated
  return (
    <svg
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: 0.045, pointerEvents: 'none' }}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <pattern id="hex-pat" x="0" y="0" width="52" height="60" patternUnits="userSpaceOnUse">
          <polygon
            points="26,2 50,15 50,45 26,58 2,45 2,15"
            fill="none"
            stroke="rgba(59,130,246,1)"
            strokeWidth="0.8"
          />
          <polygon
            points="26,32 50,45 50,75 26,88 2,75 2,45"
            fill="none"
            stroke="rgba(59,130,246,1)"
            strokeWidth="0.8"
          />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#hex-pat)" />
    </svg>
  )
}

// ── Right panel (always dark, identical in both themes) ───────────────────────
function RightPanel() {
  const count1 = useCountUp(8500, 1400)
  const count2 = useCountUp(4, 800)
  const count3 = useCountUp(6, 800)

  const stats = [
    { value: count1 === 8500 ? '8,500+' : count1.toLocaleString(), label: 'Messages trained on' },
    { value: String(count2),                                         label: 'Active personas' },
    { value: String(count3),                                         label: 'Intel categories' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5, delay: 0.1 }}
      style={{
        flex: 1,
        background: '#0a0f1e',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '40px 48px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Layer 1 — Hex grid */}
      <HexGrid />

      {/* Layer 2 — Dot grid */}
      <DotGrid />

      {/* Layer 3 — SVG noise texture */}
      <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: 0.06, pointerEvents: 'none' }}>
        <filter id="rp-noise">
          <feTurbulence type="fractalNoise" baseFrequency="0.75" numOctaves="3" stitchTiles="stitch" />
          <feColorMatrix type="saturate" values="0" />
        </filter>
        <rect width="100%" height="100%" filter="url(#rp-noise)" />
      </svg>

      {/* Layer 4 — Top-right radial bloom */}
      <div
        style={{
          position: 'absolute',
          top: -140,
          right: -140,
          width: 620,
          height: 620,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(59,130,246,0.14) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />

      {/* Layer 5 — Bottom-left radial bloom */}
      <div
        style={{
          position: 'absolute',
          bottom: -100,
          left: -100,
          width: 420,
          height: 420,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(59,130,246,0.07) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />

      {/* Layer 6 — Scan line */}
      <ScanLine />

      {/* Layer 7 — Floating data nodes */}
      <DataNodes />

      {/* LIVE pill */}
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 8 }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 7,
            padding: '5px 11px',
            border: '1px solid rgba(255,255,255,0.10)',
            background: 'rgba(255,255,255,0.04)',
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', flexShrink: 0 }} />
          <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#94a3b8', letterSpacing: '0.12em' }}>LIVE</span>
        </div>
      </div>

      {/* Center content */}
      <div style={{ position: 'relative' }}>
        {/* Shield icon with radar rings */}
        <div style={{ position: 'relative', width: 72, height: 72, marginBottom: 28, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <RadarRings />
          <div
            style={{
              position: 'relative',
              zIndex: 1,
              width: 52,
              height: 52,
              background: 'rgba(59,130,246,0.08)',
              border: '1px solid rgba(59,130,246,0.18)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={24} color="#3b82f6" />
          </div>
        </div>

        <p
          style={{
            fontFamily: 'monospace',
            fontSize: 11,
            letterSpacing: '0.18em',
            color: '#3b82f6',
            marginBottom: 20,
            textTransform: 'uppercase',
          }}
        >
          ScamShield AI
        </p>

        <h2
          style={{
            fontSize: 38,
            fontWeight: 700,
            color: '#ffffff',
            lineHeight: 1.15,
            marginBottom: 20,
            letterSpacing: '-0.02em',
          }}
        >
          Built to catch<br />scammers.
        </h2>

        <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, maxWidth: 340 }}>
          Adaptive AI personas intercept scam attempts,
          extract contact intelligence, and generate
          forensic reports — without human intervention.
        </p>

        {/* Stats */}
        <div
          style={{
            display: 'flex',
            marginTop: 36,
            borderTop: '1px solid rgba(255,255,255,0.07)',
            paddingTop: 24,
          }}
        >
          {stats.map((s, i) => (
            <div
              key={s.label}
              style={{
                flex: 1,
                paddingRight: i < stats.length - 1 ? 24 : 0,
                borderRight: i < stats.length - 1 ? '1px solid rgba(255,255,255,0.07)' : 'none',
                marginRight: i < stats.length - 1 ? 24 : 0,
              }}
            >
              <p style={{ fontFamily: 'monospace', fontSize: 22, fontWeight: 700, color: '#ffffff', lineHeight: 1 }}>
                {s.value}
              </p>
              <p style={{ fontSize: 11, color: '#475569', marginTop: 5 }}>{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Terminal card */}
      <div style={{ position: 'relative' }}>
        <TerminalLog />
      </div>
    </motion.div>
  )
}

// ── Left panel — entry ────────────────────────────────────────────────────────
function LeftPanel({ dark, onEnter, fullWidth }) {
  const formBg    = dark ? '#09090b' : '#ffffff'
  const bodyText  = dark ? '#fafafa' : '#111111'
  const muted     = dark ? '#71717a' : '#8A8A8A'
  const border    = dark ? '#27272a' : '#e4e4e7'
  const btnBg     = dark ? '#fafafa' : '#111111'
  const btnText   = dark ? '#09090b' : '#ffffff'
  const btnHover  = dark ? '#e4e4e7' : '#27272a'
  const ghostHover= dark ? '#111115' : '#fafafa'
  // Was #3f3f46 / #d4d4d8 — both failed WCAG AA on their backgrounds.
  // Use the shared muted tone so the caption + copyright stay legible.
  const footerCol = dark ? '#71717a' : '#8A8A8A'

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      style={{
        width: fullWidth ? '100%' : '42%',
        minWidth: 340,
        flexShrink: 0,
        background: formBg,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: fullWidth ? '32px 24px' : '40px 48px',
      }}
    >
      {/* Wordmark */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <div
            style={{
              width: 30,
              height: 30,
              background: dark ? '#18181b' : '#111111',
              border: `1px solid ${border}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={15} color="#3b82f6" />
          </div>
          <span style={{ fontWeight: 900, fontSize: 17, color: bodyText, letterSpacing: '-0.01em' }}>
            ScamShield
          </span>
        </div>

        <button
          onClick={() => toggleDark()}
          style={{
            background: 'none',
            border: `1px solid ${border}`,
            padding: '6px 8px',
            cursor: 'pointer',
            color: muted,
            display: 'flex',
            alignItems: 'center',
          }}
          title={dark ? 'Light mode' : 'Dark mode'}
          aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {dark ? <Sun size={13} aria-hidden="true" /> : <Moon size={13} aria-hidden="true" />}
        </button>
      </div>

      {/* Entry */}
      <div>
        <h1 style={{ fontSize: 28, fontWeight: 700, color: bodyText, marginBottom: 6, letterSpacing: '-0.03em' }}>
          Honeypot console
        </h1>
        <p style={{ fontSize: 13, color: muted, marginBottom: 32, lineHeight: 1.6 }}>
          Explore captured scam sessions, extraction statistics, and forensic
          reports — or watch the honeypot trap a scammer live in the phone demo.
        </p>

        {/* Primary — open dashboard */}
        <button
          onClick={onEnter}
          onMouseEnter={e => { e.currentTarget.style.background = btnHover }}
          onMouseLeave={e => { e.currentTarget.style.background = btnBg }}
          style={{
            width: '100%',
            padding: '12px 0',
            background: btnBg,
            color: btnText,
            border: 'none',
            borderRadius: 0,
            fontSize: 13,
            fontWeight: 600,
            cursor: 'pointer',
            letterSpacing: '0.01em',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            transition: 'background 0s',
          }}
        >
          Open Dashboard
          <ArrowRight size={14} />
        </button>

        {/* Secondary — phone demo */}
        <a
          href="/demo.html"
          onMouseEnter={e => { e.currentTarget.style.background = ghostHover }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
          style={{
            width: '100%',
            marginTop: 10,
            padding: '11px 0',
            background: 'transparent',
            color: bodyText,
            border: `1px solid ${border}`,
            fontSize: 13,
            fontWeight: 500,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            textDecoration: 'none',
            boxSizing: 'border-box',
            transition: 'background 0s',
          }}
        >
          <Smartphone size={14} />
          Watch the phone demo
        </a>

        {/* Pipeline caption */}
        <p style={{ marginTop: 14, fontSize: 10, color: footerCol, fontFamily: 'monospace', textAlign: 'center', letterSpacing: '0.04em' }}>
          featherless · distilbert · spacy ner · gpt-4o · mongodb
        </p>
      </div>

      {/* Copyright */}
      <p style={{ fontSize: 11, color: footerCol }}>
        © {new Date().getFullYear()} ScamShield AI
      </p>
    </motion.div>
  )
}

// ── Root ─────────────────────────────────────────────────────────────────────
export default function LandingPage({ onEnter }) {
  const dark = useDarkMode()
  const [narrow, setNarrow] = useState(() => window.matchMedia('(max-width: 900px)').matches)

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 900px)')
    const onChange = (e) => setNarrow(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  return (
    <div style={{ minHeight: '100vh', display: 'flex', background: dark ? '#09090b' : '#f4f4f5' }}>
      <LeftPanel dark={dark} onEnter={onEnter} fullWidth={narrow} />
      {!narrow && <RightPanel />}
    </div>
  )
}
