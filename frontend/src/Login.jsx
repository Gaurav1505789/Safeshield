import { useState } from 'react'

function Login({ onLogin }) {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()

    if (!username.trim() || !password) {
      setError('Please enter a username and password')
      return
    }

    if (mode === 'signup') {
      if (password.length < 6) {
        setError('Password must be at least 6 characters')
        return
      }

      if (password !== confirmPassword) {
        setError('Passwords do not match')
        return
      }

      localStorage.setItem(
        'safeshield-demo-account',
        JSON.stringify({ username: username.trim(), password })
      )
    } else {
      const savedAccount = localStorage.getItem('safeshield-demo-account')

      if (savedAccount) {
        const account = JSON.parse(savedAccount)

        if (account.username !== username.trim() || account.password !== password) {
          setError('Invalid username or password')
          return
        }
      }
    }

    setError('')
    onLogin()
  }

  const switchMode = () => {
    setMode(mode === 'login' ? 'signup' : 'login')
    setPassword('')
    setConfirmPassword('')
    setError('')
  }

  return (
    <div className="login-page">
      <div className="login-card">

        <div className="login-logo">
          🛡️
        </div>

        <h1>SafeShield</h1>

        <p className="login-subtitle">
          AI Cyber Risk Assistant
        </p>

        <h2>{mode === 'login' ? 'Secure Login' : 'Create your account'}</h2>

        <form onSubmit={handleSubmit}>

          <div className="login-form-group">
            <label htmlFor="username">
              Username
            </label>

            <input
              id="username"
              type="text"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>

          <div className="login-form-group">
            <label htmlFor="password">
              Password
            </label>

            <input
              id="password"
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {mode === 'signup' && (
            <div className="login-form-group">
              <label htmlFor="confirm-password">
                Confirm password
              </label>

              <input
                id="confirm-password"
                type="password"
                placeholder="Re-enter your password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
          )}

          {error && (
            <div className="login-error">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="login-button"
          >
            {mode === 'login' ? '🔐 Login' : '🛡️ Create account'}
          </button>

        </form>

        <div className="security-info">
          🔒 Secure session authentication
        </div>

        <button
          type="button"
          className="login-switch"
          onClick={switchMode}
        >
          {mode === 'login'
            ? 'No account? Create one'
            : 'Already have an account? Log in'}
        </button>

      </div>
    </div>
  )
}

export default Login