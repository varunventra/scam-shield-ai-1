# ScamShield AI — Project Memory (CLAUDE.md)

This file is auto-loaded by Claude Code at the start of every session in this repo.
Read it fully before doing anything else, then read `state.md` and `storyboard.md`
(both described below) to restore full context from any prior session — including
ones run on a different machine or after the laptop was off.

## What this project is

ScamShield AI is an agentic honeypot that detects scam messages, engages scammers with
dynamic AI personas, and extracts intelligence (phone numbers, UPI IDs, bank accounts,
phishing links) in real time. Originally built by Varun + teammates for the India AI
Impact Buildathon, later extended by a teammate (Sahith) for a separate VNR VJIET
hackathon with a better demo dashboard. This repo
(`github.com/varunventra/scam-shield-ai-1`) is Varun's own copy, stripped of
VNR-specific branding, being prepped for Varun's own upcoming university hackathon.

Stack: FastAPI (Python 3.11) backend, React + Vite + Tailwind frontend, MongoDB Atlas,
OpenAI GPT-4o (honeypot persona) + Featherless.ai (demo scammer), spaCy/TF-IDF/DistilBERT
for scam detection, deployed on Render (backend) + Vercel (frontend).

## Persistent memory system — read this carefully

Claude Code sessions don't share context with each other. This project keeps its own
memory ON DISK instead of relying on chat history:

- **`state.md`** — single source of truth for "where things stand": what's done, what's
  in progress, decisions made and why, blockers, which accounts/credentials still need
  to be set up, and the exact next action. Always read this first, every session.
- **`storyboard.md`** — a live micro-checklist for whatever task is currently active.
  Created or extended whenever the user gives a new task. Keep checkboxes updated as
  you complete each step — don't wait to be asked.

### Rules for keeping this current automatically

- When you finish a meaningful unit of work (a checklist item, a commit, a deploy step,
  a decision that changes direction, a blocker), update `state.md` and/or
  `storyboard.md` yourself, immediately. Don't wait for `/sync`.
- `/sync` is the full, deliberate refresh — run it (or the user will run it) before
  ending a session, e.g. before closing the laptop. It re-derives `state.md` from actual
  repo state (`git log`, `git status`, file contents) instead of trusting what's already
  written, so it self-corrects drift.
- `/resume` is how a new session picks the thread back up — read `state.md` +
  `storyboard.md`, summarize where things left off in a few sentences, then continue
  with the next unchecked storyboard item without making the user re-explain everything.
- A half-updated memory file is worse than none, because it actively misleads the next
  session. Prefer marking something as uncertain/unverified over stating it as done.

## Available subagents (`.claude/agents/`)

- **repo-ops** — git/GitHub operations, deployment config (`render.yaml`,
  `frontend/vercel.json`), auditing that no secrets get committed. Backs `/setup-repo`.
- **state-keeper** — maintains `state.md` and `storyboard.md`. Backs `/sync` and `/resume`.
- **code-reviewer** — reviews changes before they're committed/pushed/deployed, focused
  on what could embarrassingly break live during a hackathon demo.

## Available commands (`.claude/commands/`)

- `/setup-repo` — one-time: initializes git if needed, adds the `origin` remote,
  commits, and pushes to GitHub. Run this first, in this repo, on this machine.
- `/sync` — full state refresh; run before stopping work for the day.
- `/resume` — restore context and continue from exactly where you left off.
- `/task <description>` — start a new piece of work; generates/extends
  `storyboard.md` with a checklist for it.

## What Claude Code can and can't set up on its own

CAN (runs locally with your own git/GitHub credentials): git init/remote/commit/push,
editing code and config files, running tests/linters, editing `render.yaml` /
`frontend/vercel.json`, generating `.env` templates.

CANNOT (no browser or account access — you have to do these yourself):
- Creating the Render account/service and clicking "deploy"
- Creating the Vercel account/project and clicking "deploy"
- Creating the MongoDB Atlas cluster and getting the connection string
- Creating OpenAI / Featherless.ai API keys
- Pasting real secret values into Render/Vercel's environment variable dashboards
  (never put real secrets in files Claude can read or commit)

`state.md` tracks exactly which of these manual steps are done vs still pending.

## Conventions

- Python: `ruff check app tests` should pass clean; tests via `pytest tests/ -q`.
- Never commit `.env`, real API keys, or MongoDB URIs. `.gitignore` already covers
  `.env` — double-check `git diff --cached` before every commit anyway.
- Commit messages: short, imperative, no fluff.
