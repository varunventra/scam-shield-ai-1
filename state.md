# State

Last synced: 2026-08-19 (post-push update by repo-ops)

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

- [x] GitHub repo `varunventra/scam-shield-ai-1` — pushed and confirmed live (2026-08-19, commit e124531, branch master)
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

Repo is live on GitHub. The next steps are all manual (browser required):
1. Create MongoDB Atlas cluster, get the connection string (`MONGODB_URI`).
2. Get an OpenAI API key with GPT-4o access (`OPENAI_API_KEY`).
3. Optionally get a Featherless.ai API key (`FEATHERLESS_API_KEY`).
4. Deploy backend on Render — set all env vars listed in the Accounts section above.
5. Deploy frontend on Vercel — update `frontend/vercel.json` with the real Render URL,
   set `VITE_API_KEY` to match the backend `API_KEY`.
6. Run end-to-end smoke test.
