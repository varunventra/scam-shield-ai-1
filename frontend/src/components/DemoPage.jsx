/**
 * DemoPage — Live interception demo with two phone mockups side by side.
 *
 * Fix history:
 *  v2 — False scam detection fix, auto-mode turn limit, larger phones, correct theming
 */
import { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RotateCcw, Shield, Wifi, Battery, Signal, Square } from 'lucide-react'
import { sendMessage, generateScamMessage } from '../lib/api'
import { initDark } from '../hooks/darkMode'
import ReasoningPanel from './ReasoningPanel'
import { formatScamType as _formatScamType } from '../lib/labels'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PHONE_W = 340
const PHONE_H = 640
const GAP_W   = 140
const MAX_TURNS = 10   // hard stop for auto mode (scammer turns)

const SCAM_TYPES = [
  { id: 'sbi-kyc',    label: 'SBI KYC Fraud',    scammerName: 'SBI Customer Care',    avatar: 'S' },
  { id: 'lottery',    label: 'Lottery Scam',      scammerName: 'KBC Prize Claim',      avatar: 'K' },
  { id: 'job',        label: 'Job Offer Fraud',   scammerName: 'HR Department',        avatar: 'H' },
  { id: 'police',     label: 'Police Threat',     scammerName: 'Cyber Crime Cell',     avatar: 'C' },
  { id: 'upi-refund', label: 'UPI Refund Scam',   scammerName: 'Payment Support',      avatar: 'P' },
  { id: 'delivery',   label: 'Delivery Scam',     scammerName: 'FedEx Customs',        avatar: 'F' },
]

const SCAM_MESSAGES = {
  'sbi-kyc':
    'URGENT: Your SBI account has been blocked due to KYC expiry. Update immediately at sbi-kyc-verify.in/update or call 9876543210. Failure will result in permanent closure.',
  'lottery':
    'Congratulations! You have won Rs.25,00,000 in the SBI Lucky Draw 2024. To claim your prize call 9123456789 and pay processing fee of Rs.5000 to UPI: lottery.claim@ybl',
  'job':
    'We are hiring for work from home jobs. Earn Rs.50,000/month. No experience needed. Pay registration fee Rs.2000 to account 50100234567890 IFSC HDFC0001234. Contact HR: 8876543210',
  'police':
    'This is Mumbai Cyber Crime Cell. Your Aadhaar number has been used in illegal transactions. You will be arrested in 2 hours. Call officer Sharma immediately: 9988776655 to avoid arrest. Pay bail of Rs.10,000 to avoid custody.',
  'upi-refund':
    'Dear customer your refund of Rs.8,500 is pending. To receive it please share your UPI PIN on this link: refund-sbi.in/claim or send Rs.1 to verify: refund.verify@paytm',
  'delivery':
    'Your package is held at customs. Pay clearance fee Rs.1,500 to release it. UPI: delivery.fee@oksbi or account 1234567890123 IFSC SBIN0001234. Call: 9765432108',
}

// Scam indicator keywords — broad net covering financial, social engineering, and charity scams
const SCAM_KEYWORDS = /urgent|blocked|suspend|arrest|kyc|otp|verify|prize|lottery|refund|clearance|customs|fee|transfer|upi|account|click|link|call|pay|send|rupees|rupee|donate|donation|charity|foundation|fund|support|help us|money|amount|₹|\d{4,}|whatsapp|telegram|wallet|recharge|cashback|reward|winner|selected|helpline|helpdesk|customer care/i
const URL_RE        = /https?:\/\/|www\.|\.in\/|\.com\//i
const PHONE_RE      = /[6-9]\d{9}/

/** Returns true if the message is likely to be a real scam and should show bottom sheet */
function looksLikeScam(text) {
  if (text.length < 20) return false
  return SCAM_KEYWORDS.test(text) || URL_RE.test(text) || PHONE_RE.test(text)
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** Format an epoch-ms timestamp as a short chat time, e.g. "10:47" */
function formatMsgTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
}

function genConfidence() {
  return Math.floor(88 + Math.random() * 10)
}

function formatScamType(st) {
  if (!st) return 'Unknown Scam'
  return _formatScamType(st)
}

function mergeIntel(prev, data) {
  const intel = data?.intelligence || {}
  return {
    phoneNumbers:  [...new Set([...prev.phoneNumbers,  ...(intel.phoneNumbers  || [])])],
    upiIds:        [...new Set([...prev.upiIds,        ...(intel.upiIds        || [])])],
    bankAccounts:  [...new Set([...prev.bankAccounts,  ...(intel.bankAccounts  || [])])],
    phishingLinks: [...new Set([...prev.phishingLinks, ...(intel.phishingLinks || [])])],
  }
}

// ---------------------------------------------------------------------------
// Sub-components (always dark — phone screens never change with theme)
// ---------------------------------------------------------------------------

function TypingDots() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 5, padding: '10px 14px',
      background: '#1c1c1e', borderRadius: 16, borderBottomLeftRadius: 4,
      alignSelf: 'flex-start', marginLeft: 10,
    }}>
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          animate={{ y: [0, -5, 0] }}
          transition={{ repeat: Infinity, duration: 0.7, delay: i * 0.15 }}
          style={{ width: 7, height: 7, borderRadius: '50%', background: '#71717a' }}
        />
      ))}
    </div>
  )
}

function StatusBar() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 15000)
    return () => clearInterval(t)
  }, [])
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '2px 18px 4px', height: 30, flexShrink: 0,
    }}>
      <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#71717a', fontWeight: 600 }}>
        {now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })}
      </span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        <Signal size={11} color="#71717a" />
        <Wifi size={11} color="#71717a" />
        <Battery size={11} color="#71717a" />
      </div>
    </div>
  )
}

function ChatHeader({ name, avatar }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px 12px',
      borderBottom: '1px solid #27272a', flexShrink: 0, height: 56,
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: '50%', background: '#27272a',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 14, color: '#71717a', flexShrink: 0,
      }}>
        {avatar}
      </div>
      <div>
        <p style={{ fontSize: 14, fontWeight: 600, color: '#fafafa', lineHeight: 1.2 }}>{name}</p>
        <p style={{ fontSize: 10, color: '#71717a', fontFamily: 'monospace' }}>SMS</p>
      </div>
    </div>
  )
}

function BubbleTime({ time }) {
  if (!time) return null
  return (
    <span style={{
      display: 'block', fontSize: 9, fontFamily: 'monospace',
      color: 'rgba(255,255,255,0.45)', textAlign: 'right', marginTop: 3,
    }}>{time}</span>
  )
}

function SentBubble({ text, time }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 16, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      transition={{ duration: 0.22 }}
      style={{ alignSelf: 'flex-end', maxWidth: '82%', marginRight: 10, marginBottom: 7 }}
    >
      <div style={{
        background: '#1e3a5f', color: '#fff', fontSize: 13, lineHeight: 1.5,
        padding: '10px 14px', borderRadius: 18, borderBottomRightRadius: 4,
        wordBreak: 'break-word',
      }}>
        {text}
        <BubbleTime time={time} />
      </div>
    </motion.div>
  )
}

/** AI reply as it appears on the TARGET phone — outgoing (right-aligned) with AI badge */
function SentAIBubble({ text, time }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 16, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      transition={{ duration: 0.22 }}
      style={{ alignSelf: 'flex-end', maxWidth: '82%', marginRight: 10, marginBottom: 7, position: 'relative' }}
    >
      <div style={{ position: 'absolute', top: -9, left: 0 }}>
        <span style={{
          fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
          color: '#3b82f6', background: '#09090b',
          padding: '1px 5px', borderRadius: 3, border: '1px solid #1d4ed8',
        }}>AI</span>
      </div>
      <div style={{
        background: '#1a3a2a', color: '#fff', fontSize: 13, lineHeight: 1.5,
        padding: '10px 14px', borderRadius: 18, borderBottomRightRadius: 4,
        wordBreak: 'break-word',
      }}>
        {text}
        <BubbleTime time={time} />
      </div>
    </motion.div>
  )
}

function AIReplyBubble({ text, time }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -16, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      transition={{ duration: 0.22 }}
      style={{ alignSelf: 'flex-start', maxWidth: '82%', marginLeft: 10, marginBottom: 7, position: 'relative' }}
    >
      <div style={{ position: 'absolute', top: -9, right: 0 }}>
        <span style={{
          fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
          color: '#3b82f6', background: '#09090b',
          padding: '1px 5px', borderRadius: 3, border: '1px solid #1d4ed8',
        }}>AI</span>
      </div>
      <div style={{
        background: '#1a3a2a', color: '#fff', fontSize: 13, lineHeight: 1.5,
        padding: '10px 14px', borderRadius: 18, borderBottomLeftRadius: 4,
        wordBreak: 'break-word',
      }}>
        {text}
        <BubbleTime time={time} />
      </div>
    </motion.div>
  )
}

function ReceivedBubble({ text, time, scamBadge, safeBadge }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -16, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      transition={{ duration: 0.22 }}
      style={{ alignSelf: 'flex-start', maxWidth: '82%', marginLeft: 10, marginBottom: 7 }}
    >
      <div style={{
        background: '#1c1c1e', color: '#fff', fontSize: 13, lineHeight: 1.5,
        padding: '10px 14px', borderRadius: 18, borderBottomLeftRadius: 4,
        wordBreak: 'break-word',
      }}>
        {text}
        <AnimatePresence>
          {scamBadge && (
            <motion.span
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              style={{
                display: 'inline-block', marginLeft: 8,
                fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                color: '#ef4444', border: '1px solid #ef4444',
                padding: '1px 5px', borderRadius: 3,
              }}
            >SCAM</motion.span>
          )}
          {safeBadge && (
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4, delay: 1.8 }}
              style={{
                display: 'inline-block', marginLeft: 8,
                fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                color: '#22c55e', border: '1px solid #22c55e',
                padding: '1px 5px', borderRadius: 3,
              }}
            >SAFE</motion.span>
          )}
        </AnimatePresence>
        <BubbleTime time={time} />
      </div>
    </motion.div>
  )
}

function SystemMessage({ text, complete }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      style={{ alignSelf: 'center', display: 'flex', alignItems: 'center', gap: 5, margin: '8px 0' }}
    >
      <Shield size={10} color={complete ? '#22c55e' : '#71717a'} />
      <span style={{
        fontSize: 10, fontFamily: 'monospace',
        color: complete ? '#22c55e' : '#71717a',
        fontStyle: 'italic',
      }}>{text}</span>
    </motion.div>
  )
}

function IntelPill({ text, color, border }) {
  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.85 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      style={{
        fontSize: 9, fontFamily: 'monospace', fontWeight: 600,
        color, border: `1px solid ${border}`,
        padding: '2px 7px', borderRadius: 3, whiteSpace: 'nowrap', flexShrink: 0,
      }}
    >
      {text}
    </motion.span>
  )
}

// Phone mockup — always dark regardless of page theme
function PhoneMockup({ children, phoneBorder }) {
  return (
    <div style={{
      width: PHONE_W, height: PHONE_H, borderRadius: 40,
      background: '#0f0f0f', border: `2px solid ${phoneBorder}`,
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden', position: 'relative', flexShrink: 0,
    }}>
      {/* Notch */}
      <div style={{
        width: 70, height: 14, background: '#1a1a1a',
        borderRadius: 7, margin: '9px auto 0', flexShrink: 0,
      }} />
      {children}
    </div>
  )
}

// ---------------------------------------------------------------------------
// DemoPage
// ---------------------------------------------------------------------------

export default function DemoPage() {
  const [sessionId, setSessionId] = useState(() => crypto.randomUUID())
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))
  // Reasoning panel sits beside the phones on wide screens, below them otherwise.
  // Threshold ≈ 2 phones (820) + gap + reasoning panel (300).
  const [wideLayout, setWideLayout] = useState(
    () => window.matchMedia('(min-width: 1200px)').matches
  )

  // Mode & scam type
  const [mode, setMode] = useState('manual')
  const [selectedScamType, setSelectedScamType] = useState('sbi-kyc')
  const [inputText, setInputText] = useState('')

  // Messages
  const [leftMessages,  setLeftMessages]  = useState([])
  const [rightMessages, setRightMessages] = useState([])

  // Flow state
  const [signalDir,     setSignalDir]     = useState(null)
  const [scanning,      setScanning]      = useState(false)
  const [isLoading,     setIsLoading]     = useState(false)
  const [bottomSheet,   setBottomSheet]   = useState(null)
  const [aiEngaged,     setAiEngaged]     = useState(false)
  const [declinedBanner,setDeclinedBanner]= useState(null)
  const [error,         setError]         = useState(null)
  const [sessionDone,   setSessionDone]   = useState(false)
  const [autoRunning,   setAutoRunning]   = useState(false)

  // Intel
  const [intel, setIntel] = useState({ phoneNumbers: [], upiIds: [], bankAccounts: [], phishingLinks: [] })

  // Agent reasoning timeline (one entry per backend turn)
  const [reasoningLog, setReasoningLog] = useState([])

  const historyRef        = useRef([])
  const turnCountRef      = useRef(0)   // scammer turns sent
  const autoTimerRef      = useRef(null)
  const stopRequestRef    = useRef(false)
  const aiEngagedRef      = useRef(false)   // mirrors aiEngaged state, avoids stale closures
  const shownBottomSheetRef = useRef(false) // ensures popup shows only once per session

  const leftChatRef  = useRef(null)
  const rightChatRef = useRef(null)

  // Detect theme changes (observe html class list)
  useEffect(() => {
    initDark()
    setDark(document.documentElement.classList.contains('dark'))
    const observer = new MutationObserver(() => {
      setDark(document.documentElement.classList.contains('dark'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  // Track viewport width for the phones/reasoning layout switch
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 1200px)')
    const onChange = (e) => setWideLayout(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  useEffect(() => {
    if (leftChatRef.current)  leftChatRef.current.scrollTop  = leftChatRef.current.scrollHeight
  }, [leftMessages, isLoading])

  useEffect(() => {
    if (rightChatRef.current) rightChatRef.current.scrollTop = rightChatRef.current.scrollHeight
  }, [rightMessages])

  useEffect(() => {
    if (signalDir) {
      const t = setTimeout(() => setSignalDir(null), 800)
      return () => clearTimeout(t)
    }
  }, [signalDir])

  const intelCount = intel.phoneNumbers.length + intel.upiIds.length +
    intel.bankAccounts.length + intel.phishingLinks.length

  // -------------------------------------------------------------------------
  // Session complete helper
  // -------------------------------------------------------------------------
  const finishSession = useCallback((intelSnapshot) => {
    setSessionDone(true)
    setAutoRunning(false)
    stopRequestRef.current = true
    if (autoTimerRef.current) clearTimeout(autoTimerRef.current)

    const sysMsg = { id: 'done-' + Date.now(), text: 'Session complete — report generated', type: 'system-done', timestamp: Date.now() }
    setLeftMessages((prev)  => [...prev,  sysMsg])
    setRightMessages((prev) => [...prev,  sysMsg])
  }, [])

  // -------------------------------------------------------------------------
  // Deliver AI reply into left phone with RTL signal
  // -------------------------------------------------------------------------
  const deliverAIReply = useCallback(async (reply) => {
    if (!reply) return
    const ts = Date.now()
    historyRef.current = [...historyRef.current, { sender: 'user', text: reply, timestamp: ts }]
    // Show the AI's reply as an outgoing message on the target phone first,
    // so the user always sees exactly what the AI said on their behalf
    setRightMessages((prev) => [...prev, { id: ts + '-ai', text: reply, type: 'sent_ai', timestamp: ts }])
    setSignalDir('rtl')
    await sleep(340)
    setLeftMessages((prev) => [...prev, { id: ts.toString(), text: reply, type: 'received_ai', timestamp: ts }])
  }, [])

  // -------------------------------------------------------------------------
  // Core send flow
  // -------------------------------------------------------------------------
  const sendScamMessage = useCallback(async (text) => {
    if (isLoading || sessionDone || stopRequestRef.current) return
    setError(null)
    setIsLoading(true)

    const ts    = Date.now()
    const msgId = ts.toString()

    // 1. Scammer sent bubble
    setLeftMessages((prev) => [...prev, { id: msgId, text, type: 'sent', timestamp: ts }])

    // 2. Signal LTR
    setSignalDir('ltr')
    await sleep(440)

    // 3. Message arrives in right phone
    setRightMessages((prev) => [...prev, { id: msgId + '-r', text, type: 'received', timestamp: ts }])

    // 4. Scanning
    setScanning(true)

    // 5. API call + min scan duration
    const apiHistory = historyRef.current.map((m) => ({ sender: m.sender, text: m.text, timestamp: m.timestamp }))
    const [data] = await Promise.all([
      sendMessage(sessionId, { sender: 'scammer', text, timestamp: ts }, apiHistory)
        .catch((err) => { setError('Backend error — is backend running on port 8000?'); return null }),
      sleep(1700),
    ])

    setScanning(false)

    if (!data) { setIsLoading(false); return }

    historyRef.current = [...historyRef.current, { sender: 'scammer', text, timestamp: ts }]
    turnCountRef.current += 1

    setIntel((prev) => mergeIntel(prev, data))
    if (data.reasoning) setReasoningLog((prev) => [...prev, data.reasoning])

    // 6. Detection: trust backend scamType first; fall back to local keyword check
    const detectedScamType = data.scamType
    const backendSaysScam  = detectedScamType && detectedScamType !== 'UNKNOWN' && detectedScamType !== 'unknown'
    const messageIsScam    = backendSaysScam || looksLikeScam(text)
    // Prefer the real detection confidence from the reasoning trace; fall back
    // to a synthesized value only when the backend didn't score this turn.
    const realConf   = data.reasoning?.detectionConfidence
    const confidence = (typeof realConf === 'number' && realConf > 0)
      ? Math.round(realConf * 100)
      : genConfidence()

    if (messageIsScam && !aiEngagedRef.current && !shownBottomSheetRef.current) {
      shownBottomSheetRef.current = true
      setBottomSheet({ confidence, scamType: detectedScamType, data })
    } else if (aiEngagedRef.current) {
      await deliverAIReply(data.reply)

      // Check turn limit
      if (turnCountRef.current >= MAX_TURNS) {
        setIsLoading(false)
        finishSession(intel)
        return
      }

      if (mode === 'auto' && !stopRequestRef.current) scheduleAutoNext()
    } else {
      // Safe message
      setRightMessages((prev) => prev.map((m) => (m.id === msgId + '-r' ? { ...m, safeBadge: true } : m)))
      if (data.reply) await deliverAIReply(data.reply)
    }

    setIsLoading(false)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoading, sessionId, mode, sessionDone])

  // -------------------------------------------------------------------------
  // Engage AI
  // -------------------------------------------------------------------------
  const handleEngageAI = useCallback(async () => {
    if (!bottomSheet) return
    const { data } = bottomSheet
    setBottomSheet(null)
    setAiEngaged(true)
    aiEngagedRef.current = true

    setRightMessages((prev) => [...prev, {
      id: 'sys-' + Date.now(), text: 'ScamShield AI has taken over', type: 'system', timestamp: Date.now(),
    }])

    if (data?.reply) await deliverAIReply(data.reply)

    if (mode === 'auto') {
      setAutoRunning(true)
      scheduleAutoNext()
    }
  }, [bottomSheet, deliverAIReply, mode])

  // -------------------------------------------------------------------------
  // Decline
  // -------------------------------------------------------------------------
  const handleDecline = useCallback(() => {
    if (!bottomSheet) return
    const { confidence } = bottomSheet
    setBottomSheet(null)
    setDeclinedBanner(`SCAM DETECTED · ${confidence}% confidence`)
    setRightMessages((prev) => {
      const last = [...prev].reverse().find((m) => m.type === 'received')
      if (!last) return prev
      return prev.map((m) => (m.id === last.id ? { ...m, scamBadge: true } : m))
    })
  }, [bottomSheet])

  // -------------------------------------------------------------------------
  // Auto next
  // -------------------------------------------------------------------------
  const scheduleAutoNext = useCallback(() => {
    if (autoTimerRef.current) clearTimeout(autoTimerRef.current)
    autoTimerRef.current = setTimeout(async () => {
      if (stopRequestRef.current || turnCountRef.current >= MAX_TURNS) {
        finishSession()
        return
      }
      try {
        const history = historyRef.current.map((m) => ({
          role: m.sender === 'scammer' ? 'scammer' : 'user', text: m.text,
        }))
        const res = await generateScamMessage(selectedScamType, history)
        if (res?.message && !stopRequestRef.current) await sendScamMessage(res.message)
      } catch { /* ignore */ }
    }, 2500)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedScamType, sendScamMessage])

  // Stop button
  const handleStop = useCallback(() => {
    stopRequestRef.current = true
    setAutoRunning(false)
    if (autoTimerRef.current) clearTimeout(autoTimerRef.current)
    finishSession()
  }, [finishSession])

  useEffect(() => () => { if (autoTimerRef.current) clearTimeout(autoTimerRef.current) }, [])

  // -------------------------------------------------------------------------
  // Reset
  // -------------------------------------------------------------------------
  const handleReset = useCallback(() => {
    stopRequestRef.current    = false
    turnCountRef.current      = 0
    aiEngagedRef.current      = false
    shownBottomSheetRef.current = false
    if (autoTimerRef.current) clearTimeout(autoTimerRef.current)
    historyRef.current = []
    setSessionId(crypto.randomUUID())
    setLeftMessages([])
    setRightMessages([])
    setSignalDir(null)
    setScanning(false)
    setIsLoading(false)
    setBottomSheet(null)
    setAiEngaged(false)
    setDeclinedBanner(null)
    setError(null)
    setSessionDone(false)
    setAutoRunning(false)
    setIntel({ phoneNumbers: [], upiIds: [], bankAccounts: [], phishingLinks: [] })
    setReasoningLog([])
    setInputText('')
  }, [])

  // Switching scam type or mode mid/post-session starts a fresh session —
  // previously the buttons silently did nothing once a session completed
  const handleSelectScamType = useCallback((id) => {
    if (id === selectedScamType) return
    if (leftMessages.length > 0 || sessionDone) handleReset()
    setSelectedScamType(id)
  }, [selectedScamType, leftMessages.length, sessionDone, handleReset])

  const handleSelectMode = useCallback((m) => {
    if (m === mode) return
    if (leftMessages.length > 0 || sessionDone) handleReset()
    setMode(m)
  }, [mode, leftMessages.length, sessionDone, handleReset])

  const handleManualSend = () => {
    const t = inputText.trim()
    if (!t || isLoading || sessionDone) return
    setInputText('')
    sendScamMessage(t)
  }

  const handleAutoSend = () => {
    if (!isLoading && !sessionDone) {
      setAutoRunning(true)
      sendScamMessage(SCAM_MESSAGES[selectedScamType])
    }
  }

  // -------------------------------------------------------------------------
  // Theme — mirrors admin dashboard exactly
  // -------------------------------------------------------------------------
  const pageBg      = dark ? '#09090b'  : '#ffffff'
  const bodyText    = dark ? '#fafafa'  : '#111111'
  const mutedText   = '#71717a'
  const borderColor = dark ? '#27272a'  : '#e4e4e7'
  const phoneBorder = dark ? '#3f3f46'  : '#27272a'
  const statusBg    = dark ? '#111111'  : '#f4f4f5'

  // Mode toggle active: dark → white fill / black text; light → black fill / white text
  const toggleActiveBg   = dark ? '#fafafa' : '#111111'
  const toggleActiveText = dark ? '#111111' : '#ffffff'
  const toggleInactiveText = mutedText

  // Scam type selector active
  const scamActiveBg   = dark ? '#fafafa' : '#111111'
  const scamActiveText = dark ? '#111111' : '#ffffff'
  const scamActiveB    = dark ? '#fafafa' : '#111111'

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  return (
    <div style={{
      background: pageBg, minHeight: '100%', display: 'flex', flexDirection: 'column',
      alignItems: 'center', padding: '36px 24px 56px',
      transition: 'background 0.2s, color 0.2s',
    }}>

      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 32, maxWidth: 700 }}>
        <p style={{
          fontFamily: 'monospace', fontSize: 11, color: mutedText,
          letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 10,
        }}>Live Demo</p>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: bodyText, fontFamily: 'monospace', marginBottom: 10 }}>
          ScamShield AI — Live Interception Demo
        </h1>
        <p style={{ fontSize: 13, color: mutedText, lineHeight: 1.6 }}>
          Simulate a scam attempt and watch ScamShield detect, intercept, and extract intelligence in real time.
        </p>
      </div>

      {/* Error banner */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{
              background: '#1f0606', border: '1px solid #ef4444', borderRadius: 4,
              padding: '8px 16px', marginBottom: 20, maxWidth: 700, width: '100%',
              fontFamily: 'monospace', fontSize: 11, color: '#ef4444',
            }}
          >
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Mode toggle */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 24 }}>
        {['manual', 'auto'].map((m) => {
          const isActive = mode === m
          return (
            <button
              key={m}
              onClick={() => handleSelectMode(m)}
              style={{
                fontFamily: 'monospace', fontSize: 11, fontWeight: 700,
                textTransform: 'uppercase', letterSpacing: '0.08em',
                padding: '7px 22px',
                background: isActive ? toggleActiveBg : 'transparent',
                color: isActive ? toggleActiveText : toggleInactiveText,
                border: `1px solid ${isActive ? toggleActiveBg : borderColor}`,
                borderRadius: m === 'manual' ? '4px 0 0 4px' : '0 4px 4px 0',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >{m}</button>
          )
        })}
      </div>

      {/* Auto mode controls */}
      <AnimatePresence>
        {mode === 'auto' && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            style={{ overflow: 'hidden', width: '100%', maxWidth: PHONE_W * 2 + GAP_W, marginBottom: 20 }}
          >
            <div style={{ display: 'flex', flexWrap: 'nowrap', overflowX: 'auto', gap: 7, justifyContent: 'center', marginBottom: 14, paddingBottom: 2 }}>
              {SCAM_TYPES.map(({ id, label }) => {
                const isActive = selectedScamType === id
                return (
                  <button
                    key={id}
                    onClick={() => handleSelectScamType(id)}
                    style={{
                      fontFamily: 'monospace', fontSize: 10, fontWeight: 600,
                      textTransform: 'uppercase', letterSpacing: '0.06em',
                      padding: '6px 12px', borderRadius: 4, cursor: 'pointer',
                      background: isActive ? scamActiveBg : 'transparent',
                      color: isActive ? scamActiveText : mutedText,
                      border: `1px solid ${isActive ? scamActiveB : borderColor}`,
                      transition: 'all 0.2s',
                    }}
                  >{label}</button>
                )
              })}
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
              <button
                onClick={handleAutoSend}
                disabled={isLoading || sessionDone || autoRunning}
                style={{
                  width: PHONE_W, padding: '11px 0', fontFamily: 'monospace',
                  fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  background: isLoading || sessionDone || autoRunning ? '#1d4ed8' : '#3b82f6',
                  color: '#fff', border: 'none', borderRadius: 4,
                  cursor: (isLoading || sessionDone || autoRunning) ? 'not-allowed' : 'pointer',
                  transition: 'background 0.15s',
                }}
              >
                {autoRunning ? 'Running...' : sessionDone ? 'Session Complete' : 'Send Scam Message'}
              </button>
              {autoRunning && (
                <button
                  onClick={handleStop}
                  style={{
                    padding: '11px 18px', fontFamily: 'monospace', fontSize: 11,
                    fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
                    background: 'transparent', color: '#ef4444',
                    border: '1px solid #ef4444', borderRadius: 4, cursor: 'pointer',
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}
                >
                  <Square size={11} />
                  Stop
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Manual stop button (auto mode, once started) */}
      {mode === 'auto' && autoRunning && (
        <div style={{ display: 'none' }} /> /* handled in auto controls above */
      )}

      {/* Phones row — reasoning panel sits beside on wide screens, wraps below otherwise */}
      <div style={{
        display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
        flexWrap: 'wrap', gap: 28, maxWidth: '100%',
      }}>

        {/* Phones unit — the two phones stay together as one flex-none block */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 0, flexShrink: 0 }}>

        {/* LEFT — Scammer */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#7f3030', flexShrink: 0 }} />
            <p style={{
              fontFamily: 'monospace', fontSize: 12, letterSpacing: '0.14em', fontWeight: 700,
              textTransform: 'uppercase', color: '#c87070',
            }}>Scammer</p>
          </div>

          <PhoneMockup phoneBorder="#5a2020">
            <StatusBar />
            <ChatHeader
              name={(SCAM_TYPES.find(t => t.id === selectedScamType) || SCAM_TYPES[0]).scammerName}
              avatar={(SCAM_TYPES.find(t => t.id === selectedScamType) || SCAM_TYPES[0]).avatar}
            />

            <div ref={leftChatRef} style={{ flex: 1, overflowY: 'auto', padding: '14px 0', display: 'flex', flexDirection: 'column' }}>
              {leftMessages.length === 0 && (
                <p style={{ textAlign: 'center', fontSize: 11, fontFamily: 'monospace', color: '#3a3a3a', marginTop: 70, padding: '0 24px' }}>
                  {mode === 'manual' ? 'Type a scam message below to start.' : 'Select a scam type above and press Send.'}
                </p>
              )}
              {leftMessages.map((msg) => {
                if (msg.type === 'system' || msg.type === 'system-done')
                  return <SystemMessage key={msg.id} text={msg.text} complete={msg.type === 'system-done'} />
                if (msg.type === 'sent')
                  return <SentBubble key={msg.id} text={msg.text} time={formatMsgTime(msg.timestamp)} />
                return <AIReplyBubble key={msg.id} text={msg.text} time={formatMsgTime(msg.timestamp)} />
              })}
              {isLoading && <TypingDots />}
            </div>

            {/* Manual input bar */}
            {mode === 'manual' && !sessionDone && (
              <div style={{
                borderTop: '1px solid #27272a', display: 'flex',
                alignItems: 'center', gap: 8, padding: '8px 12px',
                height: 52, flexShrink: 0,
              }}>
                <input
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleManualSend()}
                  placeholder="Type a scam message..."
                  disabled={isLoading}
                  style={{
                    flex: 1, background: '#1a1a1a', border: '1px solid #27272a',
                    borderRadius: 20, padding: '8px 14px', fontSize: 13,
                    color: '#fafafa', outline: 'none', fontFamily: 'system-ui, sans-serif',
                  }}
                />
                <button
                  onClick={handleManualSend}
                  disabled={isLoading || !inputText.trim()}
                  style={{
                    width: 36, height: 36, borderRadius: '50%',
                    background: inputText.trim() && !isLoading ? '#3b82f6' : '#27272a',
                    border: 'none', cursor: 'pointer', display: 'flex',
                    alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                    transition: 'background 0.15s',
                  }}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="22" y1="2" x2="11" y2="13" />
                    <polygon points="22 2 15 22 11 13 2 9 22 2" />
                  </svg>
                </button>
              </div>
            )}
          </PhoneMockup>
        </div>

        {/* Signal gap */}
        <div style={{
          width: GAP_W, height: PHONE_H, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', position: 'relative',
          flexShrink: 0, marginTop: 33, gap: 10,
        }}>
          <AnimatePresence>
            {signalDir && [0, 1, 2].map((i) => (
              <motion.div
                key={signalDir + '-' + i}
                initial={{ x: signalDir === 'ltr' ? -(GAP_W / 2 - 10) : (GAP_W / 2 - 10), opacity: 0 }}
                animate={{ x: signalDir === 'ltr' ? (GAP_W / 2 - 10) : -(GAP_W / 2 - 10), opacity: [0, 1, 1, 0] }}
                transition={{ duration: 0.6, delay: i * 0.09, ease: 'easeInOut' }}
                style={{
                  position: 'absolute',
                  width: 9, height: 9, borderRadius: '50%',
                  background: '#3b82f6',
                  top: '50%', marginTop: -4,
                }}
              />
            ))}
          </AnimatePresence>
          <AnimatePresence>
            {scanning && (
              <motion.p
                key="analyzing"
                initial={{ opacity: 0 }}
                animate={{ opacity: [0, 1, 0.6, 1] }}
                exit={{ opacity: 0 }}
                transition={{ duration: 1.4, repeat: Infinity }}
                style={{
                  position: 'absolute', top: '54%',
                  fontFamily: 'monospace', fontSize: 8, fontWeight: 700,
                  color: '#3b82f6', letterSpacing: '0.12em', textTransform: 'uppercase',
                  textAlign: 'center', whiteSpace: 'nowrap',
                }}
              >
                ANALYZING
              </motion.p>
            )}
          </AnimatePresence>
        </div>

        {/* RIGHT — Target */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#1d4ed8', flexShrink: 0 }} />
            <p style={{
              fontFamily: 'monospace', fontSize: 12, letterSpacing: '0.14em', fontWeight: 700,
              textTransform: 'uppercase', color: '#93c5fd',
            }}>Target</p>
          </div>

          <PhoneMockup phoneBorder="#1e40af">
            <StatusBar />
            <ChatHeader name="Unknown Number" avatar="?" />

            {/* Declined banner */}
            <AnimatePresence>
              {declinedBanner && (
                <motion.div
                  initial={{ y: -30, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  style={{ background: '#1f0606', borderBottom: '1px solid #ef4444', padding: '5px 12px', flexShrink: 0 }}
                >
                  <p style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    {declinedBanner}
                  </p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Scanning bar */}
            <div style={{ position: 'relative', height: scanning ? 22 : 0, flexShrink: 0, overflow: 'hidden', transition: 'height 0.2s' }}>
              <AnimatePresence>
                {scanning && (
                  <motion.div
                    key="scan"
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 1.6, ease: 'easeInOut' }}
                    style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: '#3b82f6', transformOrigin: 'left' }}
                  />
                )}
              </AnimatePresence>
              {scanning && (
                <p style={{ position: 'absolute', bottom: 3, left: 12, fontSize: 8, fontFamily: 'monospace', color: '#3b82f6', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                  Scanning...
                </p>
              )}
            </div>

            {/* Chat area */}
            <div ref={rightChatRef} style={{ flex: 1, overflowY: 'auto', padding: '14px 0', display: 'flex', flexDirection: 'column' }}>
              {rightMessages.length === 0 && !scanning && (
                <p style={{ textAlign: 'center', fontSize: 11, fontFamily: 'monospace', color: '#3a3a3a', marginTop: 70, padding: '0 24px' }}>
                  Waiting for incoming message...
                </p>
              )}
              {rightMessages.map((msg) => {
                if (msg.type === 'system' || msg.type === 'system-done')
                  return <SystemMessage key={msg.id} text={msg.text} complete={msg.type === 'system-done'} />
                if (msg.type === 'sent_ai')
                  return <SentAIBubble key={msg.id} text={msg.text} time={formatMsgTime(msg.timestamp)} />
                return (
                  <ReceivedBubble
                    key={msg.id}
                    text={msg.text}
                    time={formatMsgTime(msg.timestamp)}
                    scamBadge={msg.scamBadge}
                    safeBadge={msg.safeBadge}
                  />
                )
              })}
            </div>

            {/* Intel strip */}
            <AnimatePresence>
              {intelCount > 0 && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  style={{
                    borderTop: '1px solid #27272a', padding: '7px 10px',
                    display: 'flex', flexWrap: 'wrap', gap: 5, flexShrink: 0,
                    overflow: 'hidden', maxHeight: 90, overflowY: 'auto',
                  }}
                >
                  {intel.phoneNumbers.map((p)  => <IntelPill key={p} text={p} color="#93c5fd" border="#1d4ed8" />)}
                  {intel.upiIds.map((u)        => <IntelPill key={u} text={u} color="#86efac" border="#166534" />)}
                  {intel.bankAccounts.map((b)  => <IntelPill key={b} text={b} color="#fde047" border="#854d0e" />)}
                  {intel.phishingLinks.map((l) => <IntelPill key={l} text={l.replace(/^https?:\/\//, '')} color="#fca5a5" border="#991b1b" />)}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Bottom sheet — clipped by phone overflow:hidden */}
            <AnimatePresence>
              {bottomSheet && (
                <motion.div
                  key="sheet"
                  initial={{ y: '100%' }}
                  animate={{ y: 0 }}
                  exit={{ y: '100%' }}
                  transition={{ type: 'spring', damping: 28, stiffness: 260 }}
                  style={{
                    position: 'absolute', bottom: 0, left: 0, right: 0,
                    background: '#0f0f0f',
                    borderTop: '1px solid #27272a',
                    borderRadius: '22px 22px 0 0',
                    padding: '12px 18px 22px',
                    zIndex: 10,
                  }}
                >
                  <div style={{ width: 40, height: 4, background: '#27272a', borderRadius: 2, margin: '0 auto 16px' }} />

                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444', flexShrink: 0 }} />
                    <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', letterSpacing: '0.12em' }}>
                      Scam Detected
                    </span>
                  </div>

                  <p style={{ fontFamily: 'monospace', fontSize: 36, fontWeight: 700, color: '#fafafa', lineHeight: 1, marginBottom: 3 }}>
                    {bottomSheet.confidence}%
                  </p>
                  <p style={{ fontFamily: 'monospace', fontSize: 9, color: mutedText, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 12 }}>
                    Confidence Score
                  </p>

                  <div style={{ marginBottom: 14 }}>
                    <span style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 600, color: '#ef4444', border: '1px solid #ef4444', padding: '3px 10px', borderRadius: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      {formatScamType(bottomSheet.scamType)}
                    </span>
                  </div>

                  <div style={{ borderTop: '1px solid #27272a', marginBottom: 12 }} />

                  <p style={{ fontSize: 11, color: mutedText, lineHeight: 1.6, fontFamily: 'system-ui, sans-serif', marginBottom: 16 }}>
                    ScamShield AI can take over this conversation, engage the scammer, and extract their contact details, UPI IDs, and bank accounts automatically.
                  </p>

                  <p style={{ fontSize: 10, color: '#52525b', fontFamily: 'monospace', marginBottom: 12, lineHeight: 1.5 }}>
                    AI will reply as a target, extract phone numbers, UPI IDs, and bank accounts.
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <button
                      onClick={handleEngageAI}
                      style={{
                        width: '100%', padding: '13px 0', fontFamily: 'monospace', fontSize: 11,
                        fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
                        background: '#3b82f6', color: '#fff', border: 'none',
                        borderRadius: 6, cursor: 'pointer',
                      }}
                    >✦ Let AI Take Over</button>
                    <button
                      onClick={handleDecline}
                      style={{
                        width: '100%', padding: '10px 0', fontFamily: 'monospace', fontSize: 10,
                        fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em',
                        background: 'transparent', color: '#52525b',
                        border: '1px solid #27272a', borderRadius: 6, cursor: 'pointer',
                      }}
                    >Dismiss</button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </PhoneMockup>
        </div>

        </div>{/* end phones unit */}

        {/* Agent reasoning timeline — beside on wide, below on narrow */}
        <div style={{ flexShrink: 0 }}>
          <ReasoningPanel entries={reasoningLog} height={wideLayout ? PHONE_H : 420} dark={dark} />
        </div>
      </div>{/* end phones row */}

      {/* Session complete summary */}
      <AnimatePresence>
        {sessionDone && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            style={{
              marginTop: 22, width: PHONE_W * 2 + GAP_W, maxWidth: '100%',
              background: dark ? '#0a1a0a' : '#f0faf0',
              border: '1px solid #1a3a1a', borderRadius: 6,
              padding: '12px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', items: 'center', gap: 10 }}>
              <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: '#4a7a4a', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                ✓ Session Complete
              </span>
            </div>
            <div style={{ display: 'flex', gap: 20 }}>
              <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#4a6a4a' }}>{turnCountRef.current} turns</span>
              {intelCount > 0 && <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#4a6a4a', fontWeight: 700 }}>{intelCount} intel items extracted</span>}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Status bar */}
      <div style={{
        marginTop: sessionDone ? 8 : 22, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        width: PHONE_W * 2 + GAP_W, maxWidth: '100%',
        background: statusBg, borderRadius: 4, padding: '7px 14px',
        transition: 'background 0.2s',
      }}>
        <span style={{ fontFamily: 'monospace', fontSize: 9, color: mutedText, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          Session · {sessionId.slice(0, 8)}
        </span>
        <span style={{ fontFamily: 'monospace', fontSize: 9, color: mutedText, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          {sessionDone ? 'Complete' : `Turn ${turnCountRef.current} / ${MAX_TURNS}`}
          {intelCount > 0 && ` · Intel ${intelCount}`}
        </span>
      </div>

      {/* New session button */}
      <button
        onClick={handleReset}
        style={{
          marginTop: 14, display: 'flex', alignItems: 'center', gap: 7,
          padding: '8px 18px', fontFamily: 'monospace', fontSize: 10,
          fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em',
          background: 'transparent', color: mutedText,
          border: `1px solid ${borderColor}`, borderRadius: 4, cursor: 'pointer',
          transition: 'color 0.15s',
        }}
        onMouseEnter={(e) => e.currentTarget.style.color = bodyText}
        onMouseLeave={(e) => e.currentTarget.style.color = mutedText}
      >
        <RotateCcw size={12} />
        New Session
      </button>

    </div>
  )
}
