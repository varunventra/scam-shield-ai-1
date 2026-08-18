# state.md — ScamShield AI

Last synced: 2026-08-19

---

## Snapshot

- Repo: https://github.com/varunventra/scam-shield-ai-1
- Branch: `master` — 8 commits ahead of `origin/master`. NOT pushed yet.
- Working tree after this commit: clean (3 unstaged files being committed now).
- Purpose: Varun's own university hackathon prep, built on top of the India AI Impact
  Buildathon + Sahith's VNR VJIET customization. VNR branding stripped. Git history
  was force-reset to a single clean commit on day one; subsequent commits are
  Varun's own UI/config work.

---

## Accounts / infra status

- [x] GitHub repo `varunventra/scam-shield-ai-1` — exists, has commits
- [x] MongoDB Atlas — cluster0.ovawtlh.mongodb.net — connection verified locally
- [x] OpenAI API key — in local `.env`, working
- [x] Featherless.ai API key — in local `.env`, working
- [ ] Render backend — NOT deployed. Service not created yet.
- [ ] Vercel frontend — NOT deployed. Project not created yet.
      `frontend/vercel.json` still has placeholder backend URL.
- [ ] End-to-end smoke test against live deployment
- [ ] University hackathon name / date / submission rules — not yet confirmed

---

## Local dev environment

- Python 3.11 venv at `venv/` — spaCy is incompatible with 3.14, pinned to 3.11.
- Backend: `uvicorn app.main:app --reload` on `localhost:8000`
- Frontend: `npm run dev` on `localhost:5173`
- `.env` present with all real keys — never commit it.

---

## Frontend UI state (as of 2026-08-19)

All changes committed to `master` (across 8 commits):

- Landing page removed — app loads directly into the dashboard.
- Dark mode removed — `useDarkMode` hardwired to return `false`.
- Samsung Sans Medium font added to `/public/fonts/`.
- Theme: eggshell/warm off-white body, glossy floating cards (`.glass-card`),
  white sidebar, gradient logo icon.
- Overview page title: 28px, font-weight 800.
- Top stripe: `linear-gradient(90deg, #C2410C 0%, #EA580C 100%)`.
- Accent color: **#C2410C (terracotta)** — final, user-approved.
  Tried emerald, violet, ochre (#A16207) before settling here.
- Accent still needs to be applied to `FindingsPage.jsx` and `ReportsPage.jsx`.

---

## Next steps (in order)

1. **Apply #C2410C accent** to `FindingsPage.jsx` and `ReportsPage.jsx` — any
   hardcoded old accent colors in those files.
2. **Push master to origin** — `git push origin master`.
3. **Deploy backend to Render** (manual, browser):
   - Create web service, connect `varunventra/scam-shield-ai-1` repo.
   - Set env vars: `OPENAI_API_KEY`, `FEATHERLESS_API_KEY`, `MONGODB_URI`,
     `API_KEY`, `ADMIN_API_KEY`.
   - Note the deployed service URL.
4. **Update `frontend/vercel.json`** — replace placeholder with real Render URL.
5. **Deploy frontend to Vercel** (manual, browser):
   - Connect repo, set `VITE_API_URL` to Render URL.
6. **End-to-end smoke test** — send a test scam message through the live pipeline.
7. **Prep demo script** for hackathon judging.

---

## Decisions log (append-only)

- 2026-08-18 — Cloned Sahith's VNR-customized repo, stripped VNR/"Build by Sunset"
  branding and his live deployment links from `README.md` and `frontend/vercel.json`;
  reset git history to one clean initial commit. University hackathon rules permit
  building on a prior project.
- 2026-08-19 — Removed landing page; app now goes directly to dashboard on load.
- 2026-08-19 — Removed dark mode; `useDarkMode` hook hardwired to return `false`.
- 2026-08-19 — Added Samsung Sans Medium font (woff2) to `/public/fonts/`.
- 2026-08-19 — Theme: eggshell/warm off-white body, `.glass-card` glossy floating
  cards, white sidebar.
- 2026-08-19 — Overview page title: 28px, font-weight 800.
- 2026-08-19 — Top stripe gradient: `#C2410C → #EA580C`.
- 2026-08-19 — Accent color: iterated through emerald → violet → ochre (#A16207) →
  settled on terracotta **#C2410C**. User explicitly approved. This is final.
- 2026-08-19 — Python venv locked to 3.11; spaCy incompatible with 3.14.
- 2026-08-19 — MongoDB Atlas cluster0.ovawtlh.mongodb.net verified connected locally.

---

## Known issues / blockers

- `frontend/vercel.json` backend URL is still a placeholder — frontend cannot reach
  a real backend until updated post-Render-deploy.
- `FindingsPage.jsx` and `ReportsPage.jsx` have not yet been updated to #C2410C accent.
- `ml/train_model.py` has a leftover comment referencing "India AI Impact Buildathon
  Grand Finale" — cosmetic, clean up when convenient.
- Do not attempt to merge with Sahith's original repo history — they are unrelated
  after the force-reset.
