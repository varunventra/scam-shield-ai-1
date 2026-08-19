import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || ''
const API_KEY = import.meta.env.VITE_API_KEY || ''

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': API_KEY,
  },
  // Send the admin session cookie on admin requests.
  withCredentials: true,
  // GPT-4o replies can take 10-20s; fail instead of hanging forever
  timeout: 60000,
})

/**
 * Exchange the admin key for an httpOnly session cookie.
 *
 * The admin key is NEVER read from import.meta.env: Vite inlines VITE_* values
 * into the shipped bundle as string literals, so anything referenced that way is
 * readable from devtools by every visitor. The operator types the key into the
 * dashboard once; the browser then holds only an httpOnly cookie it cannot read.
 */
export async function adminLogin(adminKey) {
  await api.post('/api/v1/admin/login', null, {
    headers: { 'x-admin-key': adminKey },
  })
  return true
}

export async function adminLogout() {
  try {
    await api.post('/api/v1/admin/logout')
  } catch {
    // Best effort: the cookie expires on its own.
  }
}

/**
 * True when the browser holds a valid admin session.
 * Probes a cheap admin endpoint; 401 means "needs login".
 */
export async function adminSessionActive() {
  try {
    await api.get('/api/v1/admin/sessions', { params: { limit: 1 } })
    return true
  } catch (err) {
    return err?.response?.status !== 401
  }
}

/**
 * Send a message to the honeypot conversation endpoint.
 */
export async function sendMessage(sessionId, message, conversationHistory = []) {
  const response = await api.post('/api/v1/conversation', {
    sessionId,
    message: {
      sender: message.sender || 'scammer',
      text: message.text,
      timestamp: message.timestamp || Date.now(),
    },
    conversationHistory: conversationHistory.map((m) => ({
      sender: m.sender || (m.role === 'scammer' ? 'scammer' : 'user'),
      text: m.text,
      timestamp: m.timestamp,
    })),
    metadata: {
      channel: 'SMS',
      locale: 'IN',
    },
  })
  return response.data
}

/**
 * Health check.
 */
export async function healthCheck() {
  const response = await axios.get(`${BASE_URL}/api/v1/health`, { timeout: 5000 })
  return response.data
}

/**
 * Generate a scam message via the backend AI scammer proxy.
 * Uses the FastAPI /api/v1/ai-scammer endpoint.
 */
export async function generateScamMessage(scamType, conversationHistory = []) {
  const response = await api.post('/api/v1/ai-scammer', {
    scamType,
    conversationHistory: conversationHistory.map((m) => ({
      role: m.role,
      text: m.text,
    })),
  })
  return response.data
}

/**
 * Fetch all sessions from MongoDB (admin endpoint).
 */
export async function fetchSessions(limit = 100) {
  try {
    const response = await api.get(`/api/v1/admin/sessions`, {
      params: { limit },
    })
    // Normalize MongoDB docs to the shape FindingsPage expects
    return (response.data.sessions || []).map(doc => {
      const intel = doc.extractedIntelligence || {}
      const turns = doc.totalMessagesExchanged || 0
      // Real detection score from the classifier (DistilBERT, rule engine as
      // fallback) — null for sessions that predate ML scoring. Never fabricated.
      const rawScore = typeof doc.mlScore === 'number' ? doc.mlScore
        : (typeof doc.ruleScore === 'number' ? doc.ruleScore : null)
      const confidence = rawScore === null ? null : Math.round(rawScore * 100)

      // Normalize scamType — backend stores uppercase enums like "OTP_FRAUD"
      const rawType = doc.scamType && doc.scamType !== 'UNKNOWN' && doc.scamType !== 'unknown'
        ? doc.scamType : (turns > 0 ? 'unknown' : 'manual')
      const scamType = rawType.toLowerCase()

      // Robust timestamp resolution — try every possible field
      const startTs = doc.createdAt || doc.updatedAt || doc.savedAt || null
      const endTs   = doc.updatedAt || doc.createdAt || null
      const savedAt = endTs ? new Date(endTs).getTime() : Date.now()

      let durationSeconds = null
      if (startTs && endTs && startTs !== endTs) {
        const diff = Math.round((new Date(endTs) - new Date(startTs)) / 1000)
        // Ignore diffs over 24h: old docs re-upserted months later would
        // otherwise report absurd "session durations"
        if (diff > 0 && diff < 86400) durationSeconds = diff
      }

      return {
        sessionId:       doc.sessionId,
        scamType,
        confidence,
        turnCount:       turns,
        durationSeconds,
        mode:            'auto',
        startTime:       startTs,
        savedAt,
        intelligence: {
          phoneNumbers:       intel.phoneNumbers       || [],
          upiIds:             intel.upiIds             || [],
          bankAccounts:       intel.bankAccounts       || [],
          phishingLinks:      intel.phishingLinks      || [],
          suspiciousKeywords: intel.suspiciousKeywords || [],
        },
        repeatScammer:   doc.repeatScammer || false,
        // Number of OTHER sessions sharing an identifier (phone/UPI/account/link)
        repeatCount:     (doc.repeatScammerSessionIds || doc.repeatSessionIds || []).length,
        repeatScore:     doc.repeatScammerScore || 0,
        riskLevel:       (doc.riskLevel || 'low').toLowerCase(),
        mlScore:         doc.mlScore,
        ruleScore:       doc.ruleScore,
        personaSelected: doc.personaSelected || null,
        detectedLanguage: doc.detectedLanguage || null,
      }
    })
  } catch (err) {
    const status = err?.response?.status
    const msg = err?.message || 'unknown error'
    console.error(`[fetchSessions] Failed: HTTP ${status ?? 'N/A'} — ${msg}`)
    if (status === 401) console.warn('[fetchSessions] Admin session missing or expired - log in again')
    throw err
  }
}

/**
 * Fetch server-aggregated stats (admin endpoint).
 * Returns the stats object, or null on failure.
 */
export async function fetchStats() {
  try {
    const response = await api.get(`/api/v1/admin/stats`)
    return response.data.stats || null
  } catch (err) {
    const status = err?.response?.status
    console.error(`[fetchStats] Failed: HTTP ${status ?? 'N/A'} — ${err?.message || 'unknown'}`)
    return null
  }
}

/**
 * Export a session's extracted intelligence as CSV or JSON.
 * Triggers a browser download. Returns true on success, false otherwise.
 */
export async function exportIntelligence(sessionId, format = 'csv') {
  try {
    const response = await api.get(`/api/v1/admin/export/${sessionId}`, {
      params: { format },
      responseType: 'blob',
    })
    const url = window.URL.createObjectURL(new Blob([response.data]))
    const link = document.createElement('a')
    link.href = url
    link.download = `intel_${sessionId}.${format}`
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
    return true
  } catch (err) {
    console.error(`[exportIntelligence] Failed: ${err?.response?.status ?? 'N/A'} — ${err?.message || 'unknown'}`)
    return false
  }
}

/**
 * Download forensic PDF from backend.
 * Returns a Blob on success, null if not found.
 */
export async function downloadForensicPDF(sessionId) {
  try {
    const response = await api.get(`/api/v1/admin/report/${sessionId}`, {
      responseType: 'blob',
    })
    return response.data
  } catch {
    return null
  }
}
