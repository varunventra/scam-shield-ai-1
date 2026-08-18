import { useState, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import AdminGate from './components/AdminGate'
import Sidebar from './components/Sidebar'
import OverviewPage from './components/OverviewPage'
import FindingsPage from './components/FindingsPage'
import ReportsPage from './components/ReportsPage'
import LandingPage from './components/LandingPage'

// Survive refreshes within a tab so visitors don't bounce back to the landing page
const ENTERED_KEY = 'scamshield_entered'

// Page-level fade+slide transition
const pageVariants = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.22, ease: 'easeOut' } },
  exit:    { opacity: 0, y: -6, transition: { duration: 0.18, ease: 'easeIn' } },
}

// Full-screen landing/dashboard swap
const screenVariants = {
  initial: { opacity: 0, scale: 0.985 },
  animate: { opacity: 1, scale: 1,   transition: { duration: 0.3, ease: 'easeOut' } },
  exit:    { opacity: 0, scale: 1.01, transition: { duration: 0.22, ease: 'easeIn' } },
}

const PAGES = {
  overview: OverviewPage,
  findings: FindingsPage,
  reports:  ReportsPage,
}

export default function App() {
  const [entered, setEntered] = useState(() => sessionStorage.getItem(ENTERED_KEY) === '1')
  const [page, setPage] = useState('overview')

  const enterDashboard = useCallback(() => {
    sessionStorage.setItem(ENTERED_KEY, '1')
    setEntered(true)
  }, [])

  const exitToLanding = useCallback(() => {
    sessionStorage.removeItem(ENTERED_KEY)
    setEntered(false)
  }, [])

  const ActivePage = PAGES[page] || OverviewPage

  return (
    <AnimatePresence mode="wait">
      {!entered ? (
        <motion.div key="landing" {...screenVariants} className="fixed inset-0 z-50">
          <LandingPage onEnter={enterDashboard} />
        </motion.div>
      ) : (
        <motion.div key="dashboard" {...screenVariants}>
          {/* Every dashboard page reads admin-only endpoints, so the session is
              established once here rather than per page. */}
          <AdminGate>
            <div className="flex h-screen bg-bg overflow-hidden">
              <Sidebar page={page} onPageChange={setPage} onExit={exitToLanding} />

              <div className="flex-1 overflow-hidden relative">
                <AnimatePresence mode="wait">
                  <motion.div key={page} {...pageVariants} className="absolute inset-0">
                    <ActivePage />
                  </motion.div>
                </AnimatePresence>
              </div>
            </div>
          </AdminGate>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
