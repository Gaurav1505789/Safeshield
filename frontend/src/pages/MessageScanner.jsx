import { useState } from 'react'
import { analyzeMessage } from '../api'
import '../pages/MessageScanner.css'

function MessageScanner({ onNavigate }) {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = async () => {
    if (!message.trim()) {
      setError('Please enter a message to analyze')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await analyzeMessage(message)
      setResult(response)
    } catch (err) {
      setError(err.detail || 'Failed to analyze message. Please try again.')
      console.error('Analysis error:', err)
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'critical'
      case 'HIGH':
        return 'high'
      case 'MEDIUM':
        return 'medium'
      case 'LOW':
        return 'low'
      default:
        return 'low'
    }
  }

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return '🔴'
      case 'HIGH':
        return '🟠'
      case 'MEDIUM':
        return '🟡'
      case 'LOW':
        return '🟢'
      default:
        return '⚪'
    }
  }

  return (
    <div className="message-scanner">
      <h2>Message Scanner</h2>

      <div className="scanner-container">
        <div className="input-section">
          <label htmlFor="message-input">Paste Suspicious Message</label>
          <textarea
            id="message-input"
            placeholder="Paste the message you want to analyze here..."
            value={message}
            onChange={(e) => {
              setMessage(e.target.value)
              setError(null)
            }}
            disabled={loading}
            rows={6}
          />
          <div className="input-footer">
            <span className="char-count">{message.length} / 5000</span>
            <button
              onClick={handleAnalyze}
              disabled={loading || !message.trim()}
              className="analyze-btn"
            >
              {loading ? 'Analyzing...' : 'Analyze Message'}
            </button>
          </div>
        </div>

        {error && (
          <div className="error-box">
            <span className="error-icon">⚠️</span>
            <p>{error}</p>
          </div>
        )}

        {loading && (
          <div className="loading-box">
            <div className="spinner"></div>
            <p>Analyzing message...</p>
          </div>
        )}

        {result && !loading && (
          <div className="result-section">
            <div className="result-header">
              <h3>Analysis Result</h3>
              <span className={`risk-badge ${getRiskColor(result.risk_level)}`}>
                {getRiskIcon(result.risk_level)} {result.risk_level}
              </span>
            </div>

            <div className="analysis-details">
              <div className={`risk-score-card ${getRiskColor(result.risk_level)}`}>
                <div className="score-value">{result.risk_score}</div>
                <div className="score-label">Risk Score</div>
                <div className="score-scale">0-100</div>
              </div>

              <div className="details-grid">
                <div className="detail-item">
                  <label>Analysis ID</label>
                  <code>{result.analysis_id}</code>
                </div>

                <div className="detail-item">
                  <label>Category</label>
                  <p>{result.category}</p>
                </div>

                <div className="detail-item full-width">
                  <label>Why?</label>
                  <div className="reasons-list">
                    {result.reasons.length > 0 ? (
                      <ul>
                        {result.reasons.map((reason, idx) => (
                          <li key={idx}>{reason}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="no-reasons">No suspicious indicators detected.</p>
                    )}
                  </div>
                </div>

                <div className="detail-item full-width">
                  <label>Recommendation</label>
                  <div className="recommendation-box">
                    <p>{result.recommendation}</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="result-actions">
              <button onClick={() => setResult(null)} className="btn-secondary">
                Analyze Another
              </button>
              <button className="btn-secondary" disabled>
                Download Report
              </button>
            </div>
          </div>
        )}

        {!result && !loading && !error && message && (
          <div className="info-box">
            <p>📝 Click "Analyze Message" to scan for cyber threats</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default MessageScanner
