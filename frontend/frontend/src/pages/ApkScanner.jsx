import { useState } from 'react'
import { analyzeApk } from '../api'
import './ApkScanner.css'

function ApkScanner({ onNavigate }) {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please choose an APK file to analyze.')
      return
    }

    if (!file.name.toLowerCase().endsWith('.apk')) {
      setError('Only .apk files are supported.')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await analyzeApk(file)
      setResult(response)
    } catch (err) {
      setError(err.detail || err.message || 'APK analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'dangerous':
        return 'dangerous'
      case 'suspicious':
        return 'suspicious'
      case 'low_risk':
        return 'low-risk'
      default:
        return 'low-risk'
    }
  }

  return (
    <div className="apk-scanner">
      <h2>APK Scanner</h2>

      <div className="apk-container">
        <div className="apk-upload-box">
          <label htmlFor="apk-file">Select APK File</label>
          <input
            id="apk-file"
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            onChange={(e) => {
              setFile(e.target.files?.[0] || null)
              setError('')
              setResult(null)
            }}
          />

          <div className="apk-actions">
            <button
              className="analyze-btn"
              onClick={handleAnalyze}
              disabled={loading || !file}
            >
              {loading ? 'Analyzing APK...' : 'Analyze APK'}
            </button>
            <button className="btn-secondary" onClick={() => onNavigate('dashboard')}>
              Back to Dashboard
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
            <p>Scanning APK for suspicious permissions and API usage...</p>
          </div>
        )}

        {result && !loading && (
          <div className="result-section">
            <div className="result-header">
              <h3>APK Analysis Result</h3>
              <span className={`risk-badge ${getVerdictColor(result.verdict)}`}>
                {result.verdict.replace('_', ' ').toUpperCase()}
              </span>
            </div>

            <div className="apk-summary-grid">
              <div className="detail-card">
                <label>File</label>
                <p>{result.file_name}</p>
              </div>
              <div className="detail-card">
                <label>Risk Score</label>
                <p>{result.risk_score}/100</p>
              </div>
              <div className="detail-card">
                <label>Package</label>
                <p>{result.package_name || 'N/A'}</p>
              </div>
              <div className="detail-card">
                <label>App Name</label>
                <p>{result.app_name || 'N/A'}</p>
              </div>
              <div className="detail-card">
                <label>Permissions</label>
                <p>{result.permission_count || 0}</p>
              </div>
              <div className="detail-card">
                <label>SHA-256</label>
                <p>{result.sha256?.slice(0, 20) || 'N/A'}...</p>
              </div>
            </div>

            <div className="detail-group">
              <h4>Suspicious permissions</h4>
              {result.suspicious_permissions?.length ? (
                <ul>
                  {result.suspicious_permissions.map((item, idx) => (
                    <li key={idx}>{item.permission} ({item.risk_points} pts)</li>
                  ))}
                </ul>
              ) : (
                <p>No suspicious permissions detected.</p>
              )}
            </div>

            <div className="detail-group">
              <h4>API findings</h4>
              {result.api_findings?.length ? (
                <ul>
                  {result.api_findings.map((item, idx) => (
                    <li key={idx}>{item.indicator} - {item.description}</li>
                  ))}
                </ul>
              ) : (
                <p>No suspicious API usage detected.</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ApkScanner
