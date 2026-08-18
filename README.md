# ScamShield AI — Agentic Honeypot for Scam Detection & Intelligence Extraction

> ScamShield is an autonomous AI system that intercepts scam messages, engages the
> scammer with a believable victim persona, and extracts actionable intelligence (phone
> numbers, UPI IDs, bank accounts, phishing links) in real time — showing its reasoning
> at every step.

- **Live dashboard:** _add your deployed dashboard URL here_
- **Live phone demo (AI vs AI):** _add your deployed demo URL here_
- **Backend API:** _add your deployed backend URL here_
- **Demo video:** _add your demo video link here_
- **Repository:** https://github.com/varunventra/scam-shield-ai-1

> **For evaluators:** everything is open — no keys, no login. The dashboard runs in
> read-only evaluation mode (`PUBLIC_DASHBOARD=true`); the phone demo is fully
> interactive. Note: if deployed on Render's free tier, the backend spins down when
> idle — the first request may take ~30–60 s to cold-start. Hit the health link above
> once and the rest is instant.

---

## Problem & Impact

India loses thousands of crores every year to phone and messaging scams (KYC fraud,
UPI refund scams, fake job offers, digital-arrest threats). Two things are missing from
today's defenses:

1. **Detection alone doesn't disrupt the scammer.** Blocking a message ends *your* risk
   but the scammer moves to the next target with the same phone number and UPI ID.
2. **The intelligence needed to actually stop them** — the scammer's payment rails and
   contact details — is only revealed *during* the conversation, which no human wants to
   have.

ScamShield flips this. Instead of hanging up, it **keeps the scammer talking** with an
autonomous victim persona, wastes their time, and harvests the exact identifiers
(UPI, bank account, phone, phishing domains) that a bank or cybercrime cell can act on —
then packages them into a forensic report and a law-enforcement-ready export.

---

## Why this is a system, not a chatbot

ScamShield is built around visible, autonomous decision-making rather than a single
prompt wrapping a static dataset:

- **3-tier detection** decides *whether* and *how* to engage (rules → ML classifier → LLM).
- **A persona engine** decides *who* to be, mirroring the identity the scammer assumes.
- **An intel-gap strategy engine** decides *what to extract next* and advances phases based
  on collected intelligence, not turn count.
- **A guardrail layer** decides *when the scammer is trying to manipulate the agent* and
  keeps it in character.
- Every one of these decisions is streamed to the dashboard as a **live reasoning trace**.

---

## Dual-LLM Architecture (Featherless.ai + GPT-4o)

ScamShield runs an **adversarial AI-vs-AI** setup across two different model families:

| Role | Provider | Model | Why |
|------|----------|-------|-----|
| **Scammer** (demo generator) | **Featherless.ai** | `Qwen/Qwen2.5-7B-Instruct` (open weights) | Serverless inference over open-weight models; drives the live phone demo |
| **Honeypot victim** | OpenAI | `gpt-4o` | Strong character consistency + prompt-injection resistance for the victim role |

**Featherless.ai** is a serverless inference platform for open-weight LLMs (Qwen, Llama,
Mistral, DeepSeek, and more) exposed through an OpenAI-compatible API. In ScamShield it
powers the scammer side of the live demo, so judges can watch two independent models —
an open-weight scammer and a GPT-4o honeypot — negotiate against each other in real time.

Configure it with `FEATHERLESS_API_KEY` (see [Environment Variables](#environment-variables)).

---

## How It Works

```
Scammer message
      │
      ▼
┌─────────────────────────┐
│ Guardrail input scan     │  detect prompt-injection / identity probes
└─────────────────────────┘
      │
      ▼
┌─────────────────────────┐
│ 3-tier scam detection    │  rules → DistilBERT/TF-IDF → LLM  ──►  confidence + scam type
└─────────────────────────┘
      │
      ▼
┌─────────────────────────┐
│ Persona + identity engine│  pick victim persona, mirror assumed identity
└─────────────────────────┘
      │
      ▼
┌─────────────────────────┐
│ Intel-gap strategy engine│  choose extraction phase from what's still missing
└─────────────────────────┘
      │
      ▼
┌─────────────────────────┐
│ Honeypot reply (GPT-4o)  │
└─────────────────────────┘
      │
      ▼
┌─────────────────────────┐
│ Guardrail output scan    │  block persona breaks / scammer-language, swap safe reply
└─────────────────────────┘
      │
      ├──► spaCy NER + regex intelligence extraction
      ├──► per-turn reasoning trace  ──►  live dashboard
      └──► MongoDB persistence, forensic PDF, repeat-scammer cross-reference
```

1. **Guardrails (input).** Every scammer message is scanned for prompt-injection,
   role-hijack, and AI-identity probes. On a hit, the agent is reinforced to stay in
   character as a confused victim.
2. **Scam detection.** 3-tier hybrid: rule engine → DistilBERT fine-tuned classifier
   (or bundled TF-IDF fallback) → LLM fallback. Returns a confidence score and one of a
   10-type taxonomy (bank impersonation, OTP/UPI fraud, lottery, job, investment,
   delivery, digital-arrest, utility, phishing). Two false-positive defenses are built
   in: an ML-positive with **zero corroboration** (no keyword hit, no URL, no phone
   number, no money amount) is downgraded to uncertain, and a single generic keyword
   cannot override an active ML "not scam" verdict.
3. **Persona selection.** Picks one of 4 victim personas (grandmother, college student,
   professional, business owner) based on scam type and scammer cues.
4. **Identity mirroring.** Detects and locks the identity the scammer assumes (name,
   gender, age) for consistent roleplay.
5. **Adaptive strategy.** 3-phase extraction engine that advances based on intel gaps,
   not just turn count — it jumps ahead when intel is already collected.
6. **Intelligence extraction.** spaCy NER EntityRuler + regex pipeline extracts phone
   numbers, UPI IDs, bank accounts, phishing links, emails, and keywords.
7. **Guardrails (output).** The generated reply is validated before it leaves the system;
   persona breaks and scammer-style language are swapped for a safe in-character fallback.
8. **Reasoning trace.** Each turn returns a decision trace (detection tier, persona
   rationale, strategy phase + trigger, missing targets, guardrail actions) rendered live.
9. **Forensic reporting.** Auto-generates PDF reports stored in MongoDB GridFS.
10. **Intel export.** One session's intelligence can be exported as CSV or JSON for a
    cybercrime-cell handoff.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend Framework | FastAPI (Python 3.11) |
| AI/LLM (demo scammer) | **Featherless.ai — `Qwen/Qwen2.5-7B-Instruct`** (open weights, OpenAI-compatible API) |
| AI/LLM (honeypot victim) | OpenAI GPT-4o (async) |
| ML Classifier | DistilBERT fine-tuned locally (HuggingFace Transformers). **Weights are gitignored (267 MB) — a fresh clone has no DistilBERT and logs an error, then falls back to TF-IDF.** Reproduce with `python ml/train_distilbert.py` |
| ML Fallback | TF-IDF + Logistic Regression (scikit-learn), bundled in-repo, trained on the 2,200-row `data/scam_dataset.csv` |
| NER Extraction | spaCy 3.x with custom EntityRuler |
| Guardrails | Regex pattern layers (prompt-injection + persona-break detection), plus a script-agnostic structural leak check |
| Database | MongoDB Atlas (async via Motor). Session documents expire via a TTL index after `DATA_RETENTION_DAYS` |
| PDF Reports | fpdf2 (in-memory generation, GridFS storage) |
| Rate Limiting | SlowAPI, per-IP: 120/min default, 30/min on `/conversation`, `/ai-scammer`, `/session/{id}/end`, 5/min on `/admin/login` |
| Cost control | Global daily token ceiling (`DAILY_TOKEN_BUDGET`); once exhausted no paid call is made |
| Frontend | React 18 + Vite + Tailwind CSS v3 |
| Animations / Charts / Icons | Framer Motion · Recharts · Lucide React |

---

## Project Structure

```
scamshield-ai/
├── app/
│   ├── api/
│   │   └── routes.py                  # All endpoints: conversation, admin, stats, export, PDF, AI scammer
│   ├── core/
│   │   ├── config.py                  # Pydantic settings (OpenAI + Featherless + Mongo)
│   │   ├── logging.py                 # Structured logging
│   │   └── security.py                # API key + admin key auth
│   ├── models/
│   │   ├── requests.py                # Request schemas
│   │   └── responses.py               # Response schemas (ConversationResponse, AgentReasoning, ...)
│   ├── services/
│   │   ├── ai_agent.py                # GPT-4o honeypot engine — persona, few-shot, strategy
│   │   ├── guardrails.py              # Prompt-injection + persona-break guardrail layers
│   │   ├── conversation_strategy.py   # Intel-gap adaptive 3-phase extraction strategy
│   │   ├── intelligence_extractor.py  # spaCy NER + regex extraction pipeline
│   │   ├── scam_detector.py           # Hybrid detection orchestrator
│   │   ├── ml_detector.py             # DistilBERT (primary) + TF-IDF (fallback) classifier
│   │   ├── persona_manager.py         # 4 dynamic victim personas
│   │   ├── language_detector.py       # Hindi / Telugu / English detection
│   │   ├── forensic_reporter.py       # PDF forensic report generator
│   │   └── callback_handler.py        # Post-session callback submission
│   ├── storage/
│   │   ├── mongodb.py                 # Session persistence, repeat detection, aggregate stats
│   │   ├── pdf_storage.py             # GridFS PDF storage
│   │   └── session_manager.py         # In-memory session state
│   ├── utils/
│   │   └── helpers.py                 # Duration / time-waste helpers, validation
│   └── main.py                        # FastAPI app entry point + startup validation
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── LandingPage.jsx        # Marketing / entry page
│       │   ├── OverviewPage.jsx       # Stats dashboard + scammer time-waste meter
│       │   ├── DemoPage.jsx           # Live two-phone interception demo
│       │   ├── ReasoningPanel.jsx     # Live per-turn agent decision timeline
│       │   ├── FindingsPage.jsx       # Sessions grid, filters, charts, CSV/JSON export
│       │   ├── ReportsPage.jsx        # Forensic PDF download list
│       │   └── Sidebar.jsx            # Navigation + dark mode toggle
│       ├── hooks/
│       │   ├── darkMode.js            # Dark mode init
│       │   └── useDarkMode.js         # MutationObserver-based dark mode hook
│       ├── lib/
│       │   └── api.js                 # Backend API calls
│       ├── main.jsx                   # Admin dashboard entry
│       └── demo-main.jsx              # Standalone demo entry (demo.html)
├── ml/
│   ├── train_distilbert.py            # DistilBERT fine-tuning (GPU)
│   ├── train_model.py                 # TF-IDF training
│   ├── download_datasets.py           # Downloads public scam/spam datasets (164K rows)
│   └── models/                        # scam_model.pkl + vectorizer.pkl (TF-IDF, bundled)
├── tests/                             # pytest suite (API, reasoning, guardrails, stats, export)
├── data/
│   └── scam_dataset.csv               # Base training dataset
├── requirements.txt
├── render.yaml                        # Render deployment config
└── .env.example                       # Environment variable template
```

---

## Setup Instructions

### Prerequisites

- Python 3.11
- Node.js 18+
- OpenAI API key (GPT-4o access)
- **Featherless.ai API key** (https://featherless.ai)
- MongoDB Atlas cluster (free tier works)
- NVIDIA GPU optional (DistilBERT); CPU fallback (TF-IDF) is bundled

### 1. Clone and Install

```bash
git clone https://github.com/varunventra/scam-shield-ai-1.git
cd scam-shield-ai-1

python3.11 -m venv venv311
venv311\Scripts\activate          # Windows
# source venv311/bin/activate     # Mac/Linux

pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
API_KEY=your-api-key-here
OPENAI_API_KEY=sk-your-openai-key
FEATHERLESS_API_KEY=your-featherless-key      # required for the demo scammer
MONGODB_URI=your-mongodb-atlas-connection-string
ADMIN_API_KEY=your-admin-key-here
```

GPT-4o plays the honeypot victim; Featherless.ai (`Qwen/Qwen2.5-7B-Instruct`, open
weights) plays the scammer in the demo. If `FEATHERLESS_API_KEY` is unset the scammer
generator falls back to OpenAI, but Featherless is the intended and default provider.

### 3. Train DistilBERT (optional)

The fine-tuned DistilBERT weights (~255 MB) are not committed. Out of the box the app
uses the bundled **TF-IDF + Logistic Regression** fallback (`ml/models/*.pkl`) — detection
works on a fresh clone. To enable DistilBERT:

```bash
python ml/download_datasets.py      # public datasets (~164K rows)
python ml/train_distilbert.py       # ~47 min on RTX 4060
```

### 4. Run the Backend

```bash
venv311\Scripts\python.exe -m uvicorn app.main:app --reload   # Windows
# uvicorn app.main:app --reload                                # Mac/Linux
```

### 5. Run the Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:5173` — backend must be at `http://localhost:8000`.

---

## API Endpoints

### POST `/api/v1/conversation`

Send a scammer message; get the honeypot reply, live extracted intelligence, and the
per-turn reasoning trace.

**Headers:** `Content-Type: application/json`, `x-api-key: your-api-key`

**Request:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account has been blocked. Call 9876543210 to reactivate.",
    "timestamp": 1739600000000
  },
  "conversationHistory": [],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

**Response (abridged):**
```json
{
  "status": "success",
  "reply": "oh no beta is my money safe? which number can i call you back on?",
  "persona": "grandmother",
  "scamType": "bank_fraud",
  "intelligence": {
    "phoneNumbers": ["9876543210"],
    "upiIds": [], "bankAccounts": [], "phishingLinks": [],
    "emailAddresses": [], "suspiciousKeywords": ["BLOCKED", "URGENT"]
  },
  "reasoning": {
    "turn": 1,
    "detectionMethod": "ml",
    "detectionConfidence": 0.98,
    "scamType": "bank_fraud",
    "personaSelected": "grandmother",
    "personaReason": "matched bank_fraud scam cues",
    "phase": 1,
    "phaseName": "Emotional Hook",
    "phaseTrigger": "first contact — build emotional hook",
    "scammerPressure": "high",
    "authorityType": "bank",
    "missingTargets": ["upi_id", "bank_account", "phishing_link"],
    "newIntelThisTurn": ["phoneNumbers: 9876543210"],
    "injectionDetected": false,
    "guardrailAction": null
  }
}
```

### POST `/api/v1/ai-scammer`

Generate a scammer message for Auto Mode (Featherless-powered AI-vs-AI).

### GET `/api/v1/admin/stats`

Aggregate dashboard stats, including scammer time wasted and average engagement
duration. Requires admin auth (open in evaluation mode).

### GET `/api/v1/admin/export/{session_id}?format=csv|json`

Export a session's extracted intelligence for law-enforcement handoff. Requires `x-admin-key`.

### GET `/api/v1/admin/report/{session_id}`

Download the forensic PDF report. Requires `x-admin-key`.

### GET `/api/v1/health`

Health check (no auth).

---

## Guardrails (Prompt-Injection Resistance)

Two independent code-level layers wrap the LLM call so the honeypot can't be manipulated
into breaking character or leaking its purpose:

- **Input scan** — detects instruction overrides ("ignore previous instructions"),
  role hijacks ("you are now…", "act as an AI"), prompt-leak probes, and AI-identity
  probes. On a hit it injects a reinforcement block so the agent responds as a confused
  human victim instead of complying.
- **Output scan** — validates every generated reply, catching persona breaks (AI
  self-disclosure, honeypot/mission leakage) and scammer-style language the victim must
  never produce. Violations are replaced with a safe in-character fallback that keeps
  extracting intel.

Guardrail activity is surfaced in the per-turn reasoning trace. Covered by `tests/test_guardrails.py`.

---

## Dashboard Features

- **Live Demo** — two phone mockups (scammer + target) with a real-time **Agent Decisions**
  timeline showing detection, persona choice, strategy phase, and intel targets per turn.
- **Overview** — aggregate stats, scam-type and intel breakdowns, detection-score
  distribution, and a **scammer time-waste meter** (total time wasted, avg per scammer).
- **Findings** — searchable/filterable sessions grid with charts and **CSV/JSON intel
  export**. Repeat offenders carry a **↺ REPEAT ×N** badge (N = other sessions sharing a
  phone/UPI/account/link), and a **REPEATS** toggle sorts the worst offenders first.
- **Reports** — one-click forensic PDF download per session, with the same repeat-count badges.
- **Dark mode** — full dark/light toggle, persisted in localStorage.

---

## Testing

```bash
# from repo root, with env vars set
python -m pytest tests/ -q
```

Suites: `test_api.py`, `test_reasoning_trace.py`, `test_guardrails.py`, `test_stats.py`,
`test_export.py`, `test_intelligence_extraction.py`, `test_forensic_reporter.py`,
`test_persona_validation.py`, `test_all_scenarios.py`. 229 tests, fully offline —
every OpenAI client is replaced with a deterministic fake (see `tests/conftest.py`).

**Code quality:** `ruff check app tests` passes clean (config in `pyproject.toml`);
`bandit`, `pip-audit`, and `npm audit` report no true positives — the few intentional
scanner suppressions are documented inline with their justification.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_KEY` | Yes | — | API authentication key |
| `OPENAI_API_KEY` | Yes | — | OpenAI API key (GPT-4o honeypot) |
| `FEATHERLESS_API_KEY` | Yes* | `""` | Featherless.ai key (demo scammer). *Falls back to OpenAI if unset |
| `MONGODB_URI` | Yes | — | MongoDB Atlas connection string. The app **refuses to start** when `DEBUG=false` and this is empty |
| `ADMIN_API_KEY` | Yes | `""` | Admin credential, min 32 chars. Exchanged once at `POST /admin/login` for an httpOnly cookie. Required when `DEBUG=false` |
| `PUBLIC_DASHBOARD` | No | `false` | Evaluation mode: read-only (GET) admin endpoints served without auth so evaluators can open the dashboard keylessly. Mutating admin routes still require the key. **Set back to `false` after the event** |
| `ALLOWED_ORIGINS` | No | `""` | Comma-separated CORS allowlist. Empty = same-origin only. `*` is stripped |
| `DAILY_TOKEN_BUDGET` | No | `2000000` | Hard daily LLM token ceiling; 0 disables the breaker |
| `MAX_MESSAGE_CHARS` | No | `4000` | Longer messages are rejected with 422 |
| `MAX_REQUEST_BYTES` | No | `262144` | Larger bodies are rejected with 413 |
| `LLM_TIMEOUT_SECONDS` | No | `20` | Outbound model call timeout |
| `DATA_RETENTION_DAYS` | No | `180` | TTL after which stored sessions (and scammer PII) are deleted |
| `FEATHERLESS_MODEL` | No | `Qwen/Qwen2.5-7B-Instruct` | Featherless model |
| `FEATHERLESS_BASE_URL` | No | `https://api.featherless.ai/v1` | Featherless API base URL |
| `OPENAI_MODEL` | No | `gpt-4o` | OpenAI model |
| `OPENAI_TEMPERATURE` | No | `0.7` | Response creativity |
| `SCAM_CONFIDENCE_THRESHOLD` | No | `0.7` | Minimum confidence to activate the agent — i.e. to spend money on an LLM call. This is the only activation gate |
| `BASE_URL` | No | auto | Base URL for PDF download links |
| `CALLBACK_URL` | No | `""` | Post-session webhook endpoint |

---

## Deploy

**Backend — Render**: connect this repo as a Blueprint; `render.yaml` defines the
service. Set `API_KEY`, `OPENAI_API_KEY`, `FEATHERLESS_API_KEY`, `MONGODB_URI`,
`ADMIN_API_KEY` in the Render environment; everything else is pre-configured in the
yaml. Push to `main` → auto-deploys.

**Frontend — Vercel**: project root is `frontend/`, framework Vite, one env var
(`VITE_API_KEY`). `frontend/vercel.json` rewrites `/api/*` to your Render backend URL —
update the `destination` in that file to point at your own deployed backend once you
have one, so the browser only ever talks to the Vercel origin (same-origin cookies
work, and CORS (`ALLOWED_ORIGINS`) never comes into play).

> **Never set a `VITE_ADMIN_KEY`.** Vite inlines every `VITE_*` value into the shipped
> bundle as a string literal, so anything referenced that way is readable by every
> visitor via devtools. The dashboard authenticates by POSTing the admin key once to
> `/api/v1/admin/login`, which returns an httpOnly cookie that JavaScript cannot read.
> During the evaluation window the dashboard instead runs with `PUBLIC_DASHBOARD=true`
> (read-only admin endpoints open, destructive ones still keyed).

---

## Team

- _add your team members here_
