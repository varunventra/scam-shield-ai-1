import { useState, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import AdminGate from './components/AdminGate'
import Sidebar from './components/Sidebar'
import OverviewPage from './components/OverviewPage'
import FindingsPage from './components/FindingsPage'
import ReportsPage from './components/ReportsPage'

// Page-level fade+slide transition
const pageVariants = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.22, ease: 'easeOut' } },
  exit:    { opacity: 0, y: -6, transition: { duration: 0.18, ease: 'easeIn' } },
}

const PAGES = {
  overview: OverviewPage,
  findings: FindingsPage,
  reports:  ReportsPage,
}

export default function App() {
  const [page, setPage] = useState('overview')
  const ActivePage = PAGES[page] || OverviewPage

  return (
    <AdminGate>
      <div className="flex h-screen overflow-hidden" style={{ background: '#EDE8E0' }}>
        <Sidebar page={page} onPageChange={setPage} />
        <div className="flex-1 overflow-hidden relative">
          <AnimatePresence mode="wait">
            <motion.div key={page} {...pageVariants} className="absolute inset-0">
              <ActivePage />
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </AdminGate>
  )
}
