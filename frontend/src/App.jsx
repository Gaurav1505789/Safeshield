import { useState, useEffect } from 'react'
import './App.css'

import Dashboard from './pages/Dashboard'
import MessageScanner from './pages/MessageScanner'
import URLScanner from './pages/URLScanner'
import ApkScanner from './pages/ApkScanner'
import Login from './Login'

import { getHealth } from './api'

function App() {
  // Current application page
  const [currentPage, setCurrentPage] = useState('dashboard')

  // Backend connection status
  const [backendConnected, setBackendConnected] = useState(false)

  // Loading state
  const [loading, setLoading] = useState(true)

  // Login state
  // This is temporary for Step 1.
  // Real authentication will be implemented later.
  const [loggedIn, setLoggedIn] = useState(false)

  useEffect(() => {
    // Check backend connection on mount
    const checkBackend = async () => {
      try {
        await getHealth()
        setBackendConnected(true)
      } catch (error) {
        console.error('Backend connection failed:', error)
        setBackendConnected(false)
      } finally {
        setLoading(false)
      }
    }

    checkBackend()
  }, [])

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onNavigate={setCurrentPage} />

      case 'message':
        return <MessageScanner onNavigate={setCurrentPage} />

      case 'url':
        return <URLScanner onNavigate={setCurrentPage} />

      case 'apk':
        return <ApkScanner onNavigate={setCurrentPage} />

      default:
        return <Dashboard onNavigate={setCurrentPage} />
    }
  }

  // --------------------------------
  // Loading screen
  // --------------------------------

  if (loading) {
    return (
      <div className="app-container">
        <div className="loading-screen">
          <div className="spinner"></div>

          <p>
            Connecting to SafeShield...
          </p>
        </div>
      </div>
    )
  }

  // --------------------------------
  // Login screen
  // --------------------------------

  if (!loggedIn) {
    return (
      <Login
        onLogin={() => setLoggedIn(true)}
      />
    )
  }

  // --------------------------------
  // Main SafeShield application
  // --------------------------------

  return (
    <div className="app-container">

      {/* Header */}

      <header className="app-header">

        <div className="header-content">

          <div className="logo-section">

            <div className="logo">
              🛡️
            </div>

            <div className="brand">

              <h1>
                SafeShield
              </h1>

              <p>
                AI Cyber Risk Assistant
              </p>

            </div>

          </div>

          {/* Backend status */}

          <div className="backend-status">

            {backendConnected ? (
              <span className="status-online">
                ● Connected
              </span>
            ) : (
              <span className="status-offline">
                ● Offline
              </span>
            )}

          </div>

        </div>

      </header>

      {/* Navigation */}

      <nav className="app-nav">

        <button
          className={`nav-btn ${
            currentPage === 'dashboard'
              ? 'active'
              : ''
          }`}
          onClick={() =>
            setCurrentPage('dashboard')
          }
        >
          Dashboard
        </button>

        <button
          className={`nav-btn ${
            currentPage === 'message'
              ? 'active'
              : ''
          }`}
          onClick={() =>
            setCurrentPage('message')
          }
        >
          Message Scanner
        </button>

        <button
          className={`nav-btn ${
            currentPage === 'url'
              ? 'active'
              : ''
          }`}
          onClick={() =>
            setCurrentPage('url')
          }
        >
          URL Scanner
        </button>

        <button
          className="nav-btn"
          disabled
        >
          Image Scanner
        </button>

        <button
          className={`nav-btn ${
            currentPage === 'apk'
              ? 'active'
              : ''
          }`}
          onClick={() =>
            setCurrentPage('apk')
          }
        >
          APK Scanner
        </button>

        <button
          className="nav-btn"
          disabled
        >
          Analysis History
        </button>

        <button
          className="nav-btn"
          disabled
        >
          Reports
        </button>

      </nav>

      {/* Main content */}

      <main className="app-main">

        {!backendConnected && (
          <div className="error-banner">
            ⚠️ Backend not connected.
            Please ensure the FastAPI server is running
            through the deployed API
          </div>
        )}

        {renderPage()}

      </main>

    </div>
  )
}

export default App