# Storyboard — live task checklist

> Auto-maintained by Claude Code. Created/extended by `/task <description>`.
> Checkboxes are updated by Claude as work actually completes — a box only gets
> checked when the thing is verifiably done, not when it's merely planned.
> Don't hand-edit this unless you're correcting a mistake Claude made.

## Task: Get ScamShield AI onto Varun's own repo and infra, ready for [hackathon name — fill in]

- [ ] Push cleaned repo to `github.com/varunventra/scam-shield-ai-1` (`/setup-repo`)
- [ ] Fill in `README.md` placeholders (team members, deployed links) once known
- [ ] Create MongoDB Atlas cluster, get connection string — **manual, browser**
- [ ] Get OpenAI API key — **manual, browser**
- [ ] (Optional) Get Featherless.ai API key — **manual, browser**
- [ ] Deploy backend to Render, set env vars — **manual, browser** (Claude can prep
      `render.yaml` beforehand)
- [ ] Deploy frontend to Vercel, set `VITE_API_KEY` — **manual, browser** (Claude can
      prep `frontend/vercel.json` beforehand)
- [ ] Update `frontend/vercel.json` destination with the real Render URL — Claude does
      this once the URL is known
- [ ] Run `pytest tests/ -q` and `ruff check app tests` clean on this machine
- [ ] End-to-end smoke test: send a test scam message through the live deployed URL
- [ ] Prep demo script / talking points for the hackathon judging round

(This section gets replaced or extended the next time you run `/task` with something new.)
