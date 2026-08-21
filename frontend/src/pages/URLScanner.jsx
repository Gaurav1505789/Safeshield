import { useState } from 'react'
import { analyzeUrl } from '../api'
import '../pages/MessageScanner.css'

function URLScanner({ onNavigate }) {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to analyze')
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await analyzeUrl(url))
    } catch (err) {
      setError(err.detail || 'Failed to analyze URL. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const riskClass = (riskLevel) => riskLevel?.toLowerCase() || 'low'

  return (
    <div className="message-scanner">
      <div className="url-page-heading">
        <div>
          <p className="url-eyebrow">SafeShield URL protection</p>
          <h2>URL Scanner</h2>
        </div>
        <button className="btn-secondary" onClick={() => onNavigate('dashboard')}>Dashboard</button>
      </div>
      <div className="scanner-container">
        <div className="input-section">
          <label htmlFor="url-input">Paste a URL to inspect</label>
          <input
            id="url-input"
            type="url"
            placeholder="https://example.com/account"
            value={url}
            onChange={(event) => { setUrl(event.target.value); setError(null) }}
            onKeyDown={(event) => { if (event.key === 'Enter') handleAnalyze() }}
            disabled={loading}
          />
          <div className="input-footer">
            <span className="char-count">Rules + machine learning</span>
            <button onClick={handleAnalyze} disabled={loading || !url.trim()} className="analyze-btn">
              {loading ? 'Analyzing...' : 'Analyze URL'}
            </button>
          </div>
        </div>

        {error && <div className="error-box"><span className="error-icon">⚠️</span><p>{error}</p></div>}
        {loading && <div className="loading-box"><div className="spinner"></div><p>Analyzing URL...</p></div>}

        {result && !loading && (
          <div className="result-section">
            <div className="result-header">
              <h3>Analysis Result</h3>
              <span className={`risk-badge ${riskClass(result.risk_level)}`}>
                {result.verdict === 'FRAUD' ? '🔴' : '🟢'} {result.verdict} · {result.risk_level}
              </span>
            </div>
            <div className="analysis-details">
              <div className={`risk-score-card ${riskClass(result.risk_level)}`}>
                <div className="score-value">{result.risk_score}</div>
                <div className="score-label">Risk Score</div>
                <div className="score-scale">0-100</div>
              </div>
              <div className="details-grid">
                <div className="detail-item full-width"><label>Normalized URL</label><code>{result.normalized_url}</code></div>
                <div className="detail-item"><label>Category</label><p>{result.category}</p></div>
                <div className="detail-item"><label>Confidence</label><p>{result.confidence}%</p></div>
                <div className="detail-item full-width"><label>Findings</label><div className="reasons-list">{result.reasons.length ? <ul>{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p className="no-reasons">No suspicious indicators detected.</p>}</div></div>
                <div className="detail-item full-width"><label>Recommendation</label><div className="recommendation-box"><p>{result.recommendation}</p></div></div>
              </div>
            </div>
            <div className="result-actions"><button onClick={() => setResult(null)} className="btn-secondary">Analyze Another</button></div>
          </div>
        )}
      </div>
    </div>
  )
}

export default URLScanner