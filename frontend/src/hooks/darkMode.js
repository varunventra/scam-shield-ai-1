// Shared dark mode helpers used by both LandingPage and Sidebar

export function applyDark(value) {
  document.documentElement.classList.toggle('dark', value)
  localStorage.setItem('scamshield_dark', value ? '1' : '0')
}

export function toggleDark() {
  const next = !document.documentElement.classList.contains('dark')
  applyDark(next)
  return next
}

export function initDark() {
  const saved = localStorage.getItem('scamshield_dark')
  if (saved === '1') {
    document.documentElement.classList.add('dark')
  }
}
