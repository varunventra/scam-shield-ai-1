# storyboard.md — live task checklist

> Auto-maintained by Claude Code. Checkboxes are only checked when work is
> verifiably done, not merely planned. Don't hand-edit unless correcting a mistake.

---

## Task: Polish UI and ship ScamShield AI to Render + Vercel

### Local / code work

- [x] Remove landing page — app goes directly to dashboard
- [x] Remove dark mode (`useDarkMode` hardwired to `false`)
- [x] Add Samsung Sans Medium font to `/public/fonts/`
- [x] Eggshell/warm off-white theme with `.glass-card` glossy floating cards
- [x] White sidebar, gradient logo icon
- [x] Overview page title: 28px, weight-800
- [x] Settle accent color on #C2410C (terracotta) — user approved
- [x] Top stripe: #C2410C → #EA580C
- [x] Commit #C2410C revert (Sidebar.jsx, OverviewPage.jsx, index.css)
- [ ] Apply #C2410C accent to `FindingsPage.jsx`
- [ ] Apply #C2410C accent to `ReportsPage.jsx`

### Git / deployment

- [ ] Push `master` to `origin/master` (`git push origin master`)
- [ ] Deploy backend to Render (manual, browser)
      — set env vars: OPENAI_API_KEY, FEATHERLESS_API_KEY, MONGODB_URI, API_KEY, ADMIN_API_KEY
- [ ] Note Render service URL, update `frontend/vercel.json` with real URL
- [ ] Deploy frontend to Vercel (manual, browser)
      — set VITE_API_URL to Render URL
- [ ] End-to-end smoke test: send a test scam message through the live deployed URL

### Demo prep

- [ ] Confirm university hackathon name, date, and submission requirements
- [ ] Prep demo script / talking points for judging round
- [ ] Fill in `README.md` placeholders (deployed links, team members if needed)
