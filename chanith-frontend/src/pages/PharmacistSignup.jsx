import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast, getDeviceId } from '../utils/api'

export default function PharmacistSignup() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    mfaCode: '',
  })
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      const result = await api('/pharmacist/signup', {
        method: 'POST',
        body: { ...formData, deviceId: getDeviceId() },
      })

      if (result.token) {
        login(result.token)
        toast('Account created successfully!', 'success')
        // Try to enroll biometric
        try {
          await enrollBiometric(result.token)
        } catch (err) {
          console.error('Biometric enrollment error:', err)
        }
        navigate('/dashboard')
      } else {
        toast('Account created. Please login.', 'success')
        navigate('/login')
      }
    } catch (err) {
      toast(err.message || 'Registration failed. Please try again.', 'error')
    } finally {
      setLoading(false)
    }
  }

  const enrollBiometric = async (token) => {
    if (!window.PublicKeyCredential) {
      throw new Error('WebAuthn is not supported in this browser.')
    }

    const enrollmentOptions = await api('/biometric/enroll/start', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
    })

    const challengeBuffer = Uint8Array.from(atob(enrollmentOptions.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const userIdBuffer = Uint8Array.from(atob(enrollmentOptions.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))

    const publicKeyCredentialCreationOptions = {
      challenge: challengeBuffer,
      rp: enrollmentOptions.rp,
      user: {
        id: userIdBuffer,
        name: enrollmentOptions.user.name,
        displayName: enrollmentOptions.user.displayName,
      },
      pubKeyCredParams: enrollmentOptions.pubKeyCredParams,
      authenticatorSelection: enrollmentOptions.authenticatorSelection,
      timeout: enrollmentOptions.timeout,
      attestation: enrollmentOptions.attestation,
    }

    toast('Please scan your fingerprint or face when prompted...', 'info')

    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    })

    const credentialForServer = {
      id: credential.id,
      rawId: Array.from(new Uint8Array(credential.rawId)),
      response: {
        attestationObject: Array.from(new Uint8Array(credential.response.attestationObject)),
        clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
      },
      type: credential.type,
    }

    const result = await api('/biometric/enroll/complete', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: {
        credential: credentialForServer,
        challenge: enrollmentOptions.challenge,
        deviceName: 'Primary Device',
      },
    })

    if (result.ok) {
      toast('Biometric enrolled successfully!', 'success')
    }
  }

  return (
    <div className="auth-container">
      <aside className="auth-sidebar">
        <div className="auth-sidebar-logo">
          <div className="medical-icon">+</div>
        </div>
        <nav className="auth-sidebar-nav">
          <Link to="/" className="auth-nav-item">
            <div className="auth-nav-icon">🏠</div>
            <span>Home</span>
          </Link>
          <Link to="/login" className="auth-nav-item">
            <div className="auth-nav-icon">🔐</div>
            <span>Login</span>
          </Link>
          <div className="auth-nav-item active">
            <div className="auth-nav-icon">👤</div>
            <span>Register</span>
          </div>
        </nav>
      </aside>

      <main className="auth-main">
        <div className="auth-card">
          <h1>Pharmacist Registration</h1>
          <p>Create your account to access the pharmacy management system</p>

          <form onSubmit={handleSubmit}>
            <div className="auth-form-group">
              <label className="auth-form-label">Username *</label>
              <input
                type="text"
                className="auth-form-input"
                value={formData.username}
                onChange={(e) => {
                  const cleaned = String(e.target.value || '')
                    .replace(/[^A-Za-z0-9._-]/g, '')
                    .slice(0, 32)
                  setFormData({ ...formData, username: cleaned })
                }}
                placeholder="pharmacist1"
                required
                maxLength={32}
              />
              <small style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                3-32 characters, letters/numbers/._-
              </small>
            </div>

            <div className="auth-form-group">
              <label className="auth-form-label">Email *</label>
              <input
                type="email"
                className="auth-form-input"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="pharmacist@example.com"
                required
              />
            </div>

            <div className="auth-form-group">
              <label className="auth-form-label">Password *</label>
              <input
                type="password"
                className="auth-form-input"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                placeholder="Choose a strong password"
                required
                minLength="8"
              />
              <small style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                Minimum 8 characters
              </small>
            </div>

            <div className="auth-form-group">
              <label className="auth-form-label">Registration Code (MFA) *</label>
              <input
                type="text"
                className="auth-form-input"
                value={formData.mfaCode}
                onChange={(e) => setFormData({ ...formData, mfaCode: e.target.value })}
                placeholder="123456"
                required
                maxLength="6"
              />
              <small style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                Demo MFA code: 123456
              </small>
            </div>

            <button type="submit" className="auth-btn-primary" disabled={loading}>
              {loading ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>

          <div className="auth-divider">
            <span>or</span>
          </div>

          <div className="auth-link">
            <p>Already have an account? <Link to="/login">Sign In</Link></p>
            <p style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--healthcare-text-muted)' }}>
              After registration, you'll need to login and enroll your biometric to access the dashboard.
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}
