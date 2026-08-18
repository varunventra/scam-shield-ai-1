# State

Last synced: not yet run — run `/sync` once, in Claude Code, in this repo, to stamp this.

## Snapshot

- Target repo: https://github.com/varunventra/scam-shield-ai-1 — verify with
  `git remote -v` / `git log` whether this has actually been pushed yet.
- Local git history: reset to a single clean commit ("Initial commit: ScamShield AI
  honeypot"). VNR branding, hackathon judging-criteria section, team credits, and
  Sahith's live deployment links were stripped from `README.md`.
  `frontend/vercel.json`'s backend destination is a placeholder
  (`REPLACE-WITH-YOUR-RENDER-BACKEND-URL`) pending your own Render deploy.
- Purpose: prepping this project for Varun's own university hackathon (previously
  built for the India AI Impact Buildathon, then customized by Sahith for VNR VJIET's
  "Build by Sunset").

## Accounts / infra status

- [ ] GitHub repo `varunventra/scam-shield-ai-1` — pushed and confirmed live
- [ ] MongoDB Atlas cluster created, connection string obtained
- [ ] OpenAI API key obtained (GPT-4o access)
- [ ] Featherless.ai API key obtained (optional — falls back to OpenAI if unset)
- [ ] Render backend deployed, env vars set (`API_KEY`, `OPENAI_API_KEY`,
      `FEATHERLESS_API_KEY`, `MONGODB_URI`, `ADMIN_API_KEY`)
- [ ] Vercel frontend deployed, `frontend/vercel.json` updated with the real Render
      backend URL, `VITE_API_KEY` set
- [ ] End-to-end smoke test against the live deployment
- [ ] University hackathon name / date / rules confirmed (fill in once known)

## Current task

Nothing active yet — run `/task <description>` in Claude Code to start one.

## Recent decisions / log

- 2026-08-18 — Cloned Sahith's VNR-customized repo, stripped VNR/"Build by Sunset"
  branding, team credits, and his live deployment links from `README.md` and
  `frontend/vercel.json`; reset git history to one clean commit so the new repo has no
  trace of his authorship/commit history. Confirmed the university hackathon's rules
  permit building on a prior project, so this is not a rules violation.

## Known issues / blockers

- Local git history was force-reset — do not attempt to merge with Sahith's original
  repo history, they're unrelated now.
- `frontend/vercel.json` destination URL is a placeholder — the frontend will not talk
  to a real backend until this is fixed post-Render-deploy.
- `ml/train_model.py` still has a leftover comment referencing "India AI Impact
  Buildathon Grand Finale" — cosmetic, not blocking, clean up whenever convenient.

## Next step (exact action to resume on)

Run `/setup-repo` in Claude Code, inside this project folder, on your machine — it
will push this to GitHub without you typing git commands. After that, the next
blocker is entirely manual: MongoDB Atlas + OpenAI key + Render + Vercel accounts.
