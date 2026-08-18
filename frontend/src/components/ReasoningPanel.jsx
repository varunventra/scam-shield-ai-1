/**
 * ReasoningPanel — live agent decision timeline for the demo view.
 *
 * Renders one card per turn from the backend `reasoning` block:
 * detection tier + confidence, persona rationale, strategy phase +
 * trigger, scammer pressure, and intel newly extracted this turn.
 */
import { motion, AnimatePresence } from 'framer-motion'
import { Brain } from 'lucide-react'
import { useEffect, useRef } from 'react'

const PHASE_COLORS = {
  1: { color: '#93c5fd', border: '#1d4ed8' },   // Emotional Hook
  2: { color: '#fde047', border: '#854d0e' },   // Active Extraction
  3: { color: '#fca5a5', border: '#991b1b' },   // Deep Extraction
}

const PRESSURE_COLORS = {
  low:        '#71717a',
  medium:     '#fde047',
  high:       '#fb923c',
  aggressive: '#ef4444',
}

function Row({ label, children }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', marginBottom: 4 }}>
      <span style={{
        fontSize: 8, fontFamily: 'monospace', color: '#52525b',
        textTransform: 'uppercase', letterSpacing: '0.08em',
        width: 56, flexShrink: 0, textAlign: 'right',
      }}>{label}</span>
      <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#a1a1aa', lineHeight: 1.5, wordBreak: 'break-word' }}>
        {children}
      </span>
    </div>
  )
}

function Chip({ text, color = '#a1a1aa', border = '#3f3f46' }) {
  return (
    <span style={{
      fontSize: 8, fontFamily: 'monospace', fontWeight: 600,
      color, border: `1px solid ${border}`,
      padding: '1px 6px', borderRadius: 3,
      textTransform: 'uppercase', letterSpacing: '0.05em',
      whiteSpace: 'nowrap',
    }}>{text}</span>
  )
}

function TurnCard({ entry }) {
  const phaseStyle = PHASE_COLORS[entry.phase] || PHASE_COLORS[1]
  const confidence = entry.detectionConfidence != null
    ? `${Math.round(entry.detectionConfidence * 100)}%` : '—'

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      style={{
        border: '1px solid #27272a', borderRadius: 4,
        padding: '10px 12px', marginBottom: 8, background: '#111113',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#fafafa', letterSpacing: '0.1em' }}>
          TURN {entry.turn}
        </span>
        <Chip
          text={`P${entry.phase} · ${entry.phaseName || ''}`}
          color={phaseStyle.color}
          border={phaseStyle.border}
        />
      </div>

      <Row label="Detect">
        {entry.detectionMethod || 'n/a'} · {confidence}
        {entry.scamType ? ` · ${entry.scamType}` : ''}
      </Row>
      <Row label="Persona">
        {entry.personaSelected || '—'}
        {entry.personaReason ? ` — ${entry.personaReason}` : ''}
      </Row>
      <Row label="Phase">{entry.phaseTrigger || '—'}</Row>
      <Row label="Scammer">
        <span style={{ color: PRESSURE_COLORS[entry.scammerPressure] || '#a1a1aa' }}>
          {entry.scammerPressure} pressure
        </span>
        {entry.authorityType && entry.authorityType !== 'unknown'
          ? ` · posing as ${entry.authorityType.replace(/_/g, ' ')}` : ''}
      </Row>

      {entry.guardrailAction && (
        <div style={{ marginTop: 6 }}>
          <Chip text={`🛡 ${entry.guardrailAction}`} color="#fca5a5" border="#991b1b" />
        </div>
      )}

      {entry.newIntelThisTurn?.length > 0 && (
        <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {entry.newIntelThisTurn.map((item) => (
            <Chip key={item} text={`+ ${item}`} color="#86efac" border="#166534" />
          ))}
        </div>
      )}

      {entry.missingTargets?.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <Row label="Next">
            hunting {entry.missingTargets.slice(0, 3).map((t) => t.replace(/_/g, ' ')).join(', ')}
          </Row>
        </div>
      )}
    </motion.div>
  )
}

export default function ReasoningPanel({ entries, height, dark }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [entries])

  const borderColor = dark ? '#27272a' : '#e4e4e7'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
        <Brain size={12} color="#4ade80" />
        <p style={{
          fontFamily: 'monospace', fontSize: 12, letterSpacing: '0.14em', fontWeight: 700,
          textTransform: 'uppercase', color: '#4ade80',
        }}>Agent Decisions</p>
      </div>

      <div style={{
        width: 300, height, borderRadius: 8,
        background: '#0f0f0f', border: `1px solid ${borderColor}`,
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', padding: '12px 10px' }}>
          {entries.length === 0 && (
            <p style={{
              textAlign: 'center', fontSize: 10, fontFamily: 'monospace',
              color: '#3a3a3a', marginTop: 70, padding: '0 20px', lineHeight: 1.7,
            }}>
              Agent reasoning appears here — detection tier, persona choice,
              extraction phase, and intel targets for every turn.
            </p>
          )}
          <AnimatePresence>
            {entries.map((entry, i) => (
              <TurnCard key={`${entry.turn}-${i}`} entry={entry} />
            ))}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
