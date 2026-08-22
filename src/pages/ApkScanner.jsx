import { useState } from 'react'
import { analyzeApk, analyzeApkUrl } from '../api'
import './ApkScanner.css'

function ApkScanner({ onNavigate }) {
  const [file, setFile] = useState(null)
  const [apkUrl, setApkUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleAnalyzeFile = async () => {
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

  const handleAnalyzeUrl = async () => {
    const cleanedUrl = apkUrl.trim()

    if (!cleanedUrl) {
      setError('Please paste an APK download URL first.')
      return
    }

    if (!/^https?:\/\//i.test(cleanedUrl)) {
      setError('Please enter a valid HTTP or HTTPS APK URL.')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await analyzeApkUrl(cleanedUrl)
      setResult(response)
    } catch (err) {
      setError(err.detail || err.message || 'APK URL preview failed.')
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

  const getVerdictLabel = (verdict) => {
    switch (verdict) {
      case 'dangerous':
        return 'Dangerous'
      case 'suspicious':
        return 'Suspicious'
      case 'low_risk':
        return 'Low Risk'
      default:
        return 'Low Risk'
    }
  }

  const getThreatSummary = (result) => {
    if (!result) return ''

    if (result.verdict === 'dangerous') {
      return 'This APK shows dangerous behavior and should not be installed or trusted without verification.'
    }

    if (result.verdict === 'suspicious') {
      return 'This APK contains several risky indicators that may indicate privacy or security concerns.'
    }

    return 'This APK looks relatively safe based on its declared permissions and code-level indicators.'
  }

  const getRecommendation = (result) => {
    if (!result) return ''

    if (result.verdict === 'dangerous') {
      return 'Avoid installation. Remove the app, verify the source, and scan it with a trusted security tool before use.'
    }

    if (result.verdict === 'suspicious') {
      return 'Exercise caution. Review the permissions and only install from a trusted vendor after additional verification.'
    }

    return 'No immediate threat was detected, but it is still wise to verify the app source and keep the device updated.'
  }

  const getWarningState = (result) => {
    if (!result) return null

    if (result.risk_score >= 70) {
      return {
        tone: 'danger',
        title: 'High-risk APK detected',
        message:
          'This APK shows a high risk profile. Do not install it unless you independently verify the source and trust the package.',
      }
    }

    if (result.risk_score >= 35) {
      return {
        tone: 'warning',
        title: 'Caution recommended',
        message:
          'This APK shows several suspicious indicators. Review the permissions and verify the source before downloading.',
      }
    }

    return {
      tone: 'safe',
      title: 'Low-risk preview',
      message:
        'This APK appears relatively low risk based on the checked permissions and code indicators.',
    }
  }

  const getTrustScore = (riskScore) => Math.max(0, Math.min(100, 100 - riskScore))

  const getTrustLabel = (riskScore) => {
    if (riskScore >= 75) return 'Very Low Trust'
    if (riskScore >= 50) return 'Low Trust'
    if (riskScore >= 25) return 'Moderate Trust'
    return 'High Trust'
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
              onClick={handleAnalyzeFile}
              disabled={loading || !file}
            >
              {loading ? 'Analyzing APK...' : 'Analyze APK File'}
            </button>
          </div>
        </div>

        <div className="apk-url-box">
          <label htmlFor="apk-url">Paste APK Download URL</label>
          <input
            id="apk-url"
            type="url"
            placeholder="https://example.com/app.apk"
            value={apkUrl}
            onChange={(e) => {
              setApkUrl(e.target.value)
              setError('')
              setResult(null)
            }}
          />

          <div className="apk-actions">
            <button
              className="analyze-btn secondary"
              onClick={handleAnalyzeUrl}
              disabled={loading || !apkUrl.trim()}
            >
              {loading ? 'Previewing APK...' : 'Preview APK URL'}
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
          <div className="result-section apk-result-section">
            <div className="result-header">
              <div>
                <p className="section-tag">APK Security Report</p>
                <h3>{result.file_name}</h3>
              </div>
              <span className={`risk-badge ${getVerdictColor(result.verdict)}`}>
                {getVerdictLabel(result.verdict)}
              </span>
            </div>

            <div className="summary-grid">
              <div className="summary-card score-card">
                <span className="summary-label">Risk Score</span>
                <strong>{result.risk_score}</strong>
                <small>out of 100</small>
              </div>

              <div className="summary-card trust-card">
                <span className="summary-label">Trust Score</span>
                <strong>{getTrustScore(result.risk_score)}</strong>
                <small>{getTrustLabel(result.risk_score)}</small>
                <div className="trust-meter">
                  <div
                    className="trust-meter-fill"
                    style={{ width: `${getTrustScore(result.risk_score)}%` }}
                  />
                </div>
              </div>

              <div className="summary-card">
                <span className="summary-label">Package</span>
                <strong>{result.package_name || 'N/A'}</strong>
              </div>

              <div className="summary-card">
                <span className="summary-label">App Name</span>
                <strong>{result.app_name || 'N/A'}</strong>
              </div>

              <div className="summary-card">
                <span className="summary-label">File Size</span>
                <strong>{result.file_size_mb || 0} MB</strong>
              </div>
            </div>

            {(() => {
              const warning = getWarningState(result)

              return (
                <div className={`warning-banner ${warning?.tone || 'safe'}`}>
                  <strong>{warning?.title}</strong>
                  <p>{warning?.message}</p>
                </div>
              )
            })()}

            <div className="insight-panel">
              <h4>Threat Summary</h4>
              <p>{getThreatSummary(result)}</p>
            </div>

            <div className="meta-grid">
              <div className="meta-item">
                <label>Version</label>
                <p>{result.version_name || 'Unknown'}</p>
              </div>
              <div className="meta-item">
                <label>Permissions</label>
                <p>{result.permission_count || 0}</p>
              </div>
              <div className="meta-item">
                <label>SHA-256</label>
                <p>{result.sha256 || 'N/A'}</p>
              </div>
            </div>

            {result.download_url && (
              <div className="download-panel">
                <h4>Download Decision</h4>
                <p>
                  {result.risk_score >= 70
                    ? 'This APK was flagged as high risk. Review the warning before deciding whether to download.'
                    : 'Preview loaded successfully. You can choose whether to continue to the download.'}
                </p>

                {result.risk_score >= 70 ? (
                  <button className="download-link blocked" type="button" disabled>
                    Blocked: High risk detected
                  </button>
                ) : (
                  <a
                    href={result.download_url}
                    target="_blank"
                    rel="noreferrer"
                    className="download-link"
                  >
                    Proceed to download
                  </a>
                )}
              </div>
            )}

            <div className="recommendation-box">
              <h4>Recommended Action</h4>
              <p>{getRecommendation(result)}</p>
            </div>

            <div className="detail-grid">
              <div className="detail-group">
                <h4>Suspicious Permissions</h4>
                {result.suspicious_permissions?.length ? (
                  <ul>
                    {result.suspicious_permissions.map((item, idx) => (
                      <li key={idx}>
                        <span>{item.permission}</span>
                        <em>{item.risk_points} pts</em>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>No suspicious permissions detected.</p>
                )}
              </div>

              <div className="detail-group">
                <h4>API & Code Findings</h4>
                {result.api_findings?.length ? (
                  <ul>
                    {result.api_findings.map((item, idx) => (
                      <li key={idx}>
                        <strong>{item.indicator}</strong>
                        <span>{item.description}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>No suspicious API usage detected.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ApkScanner
