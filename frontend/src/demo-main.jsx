import React from 'react'
import ReactDOM from 'react-dom/client'
import DemoPage from './components/DemoPage'
import './index.css'
import { initDark } from './hooks/darkMode'

initDark()

ReactDOM.createRoot(document.getElementById('demo-root')).render(
  <React.StrictMode>
    <DemoPage />
  </React.StrictMode>
)
