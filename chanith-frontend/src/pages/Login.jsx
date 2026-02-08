import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast, getDeviceId, getRememberTokenForIdentifier, setRememberTokenForIdentifier } from '../utils/api'

export default function Login() {
  const navigate = useNavigate()
  const { login, token } = useAuth()
  const [identifier, setIdentifier] = useState('doctor1')
  const [password, setPassword] = useState('password123')
  const [mfaCode, setMfaCode] = useState('')
  const [showOtp, setShowOtp] = useState(false)
  const [otpData, setOtpData] = useState(null)
  const [otp, setOtp] = useState('')
  const [rememberDevice, setRememberDevice] = useState(true)
  const [showClinicCode, setShowClinicCode] = useState(false)
  const [clinicCode, setClinicCode] = useState('')
  const [clinicCodeUsername, setClinicCodeUsername] = useState('')

  useEffect(() => {
    if (token) {
      navigate('/dashboard')
    }
  }, [token, navigate])

  // If user clicked a magic link (new-device step-up), consume it and log in.
  useEffect(() => {
    const url = new URL(window.location.href)
    const mlt = url.searchParams.get('mlt')
    if (!mlt) return
    ;(async () => {
      try {
        const out = await api('/auth/magic-link/consume', {
          method: 'POST',
          body: { token: mlt, deviceId: getDeviceId() },
        })
        url.searchParams.delete('mlt')
        window.history.replaceState({}, '', url.toString())
        login(out.token)
        toast('Device verified. Logged in.', 'success')
        navigate('/dashboard')
      } catch (err) {
        toast(`Magic link failed: ${err.message}`, 'error')
      }
    })()
  }, [login, navigate])

  const handleLogin = async (e) => {
    e.preventDefault()
    try {
      const rememberToken = getRememberTokenForIdentifier(identifier) || undefined
      const data = await api('/auth/login', {
        method: 'POST',
        body: {
          identifier,
          password,
          mfaCode: mfaCode || undefined,
          deviceId: getDeviceId(),
          rememberToken,
        },
      })

      if (data.mfaRequired && data.method === 'EMAIL_OTP') {
        setOtpData(data)
        setShowOtp(true)
        toast(data.delivery === 'email' ? 'OTP sent to your email.' : 'OTP issued (MVP). Check server logs.', 'warning')
        return
      }

      if (data.mfaRequired && data.method === 'EMAIL_LINK') {
        toast('Verification link sent to your email. Open it to finish login.', 'warning')
        return
      }

      if (data.token) {
        login(data.token)
        navigate('/dashboard')
        return
      }

      throw new Error(data.message || data.error || 'Login failed')
    } catch (err) {
      console.error('Login error:', err)
      if (err.message && err.message.includes('account_pending_admin_approval')) {
        toast('Account pending admin approval. You will receive an email once activated.', 'warning')
        return
      }
      // Check if patient needs clinic code verification
      if (err.message && err.message.includes('patient_not_verified')) {
        setShowClinicCode(true)
        setClinicCodeUsername(identifier)
        toast('Account created but not verified. Please enter your clinic verification code.', 'warning')
        return
      }
      // Provide more helpful error messages
      let errorMessage = err.message
      if (err.message.includes('fetch') || err.message.includes('NetworkError')) {
        errorMessage = 'Cannot connect to server. Please make sure the backend is running on http://localhost:3000'
      } else if (err.message.includes('invalid') || err.message.includes('credentials')) {
        errorMessage = 'Invalid credentials. Please check your username, password, and MFA code.'
      }
      toast(errorMessage, 'error')
    }
  }

  const handleOtpVerify = async (e) => {
    e.preventDefault()
    try {
      const data = await api('/auth/verify-otp', {
        method: 'POST',
        body: {
          otpRequestId: otpData.otpRequestId,
          otp,
          rememberDevice,
          deviceId: getDeviceId(),
        },
      })

      if (data.rememberToken) {
        setRememberTokenForIdentifier(identifier, data.rememberToken)
      }
      if (data.token) {
        login(data.token)
        navigate('/dashboard')
      } else {
        throw new Error(data.message || data.error || 'OTP verification failed')
      }
    } catch (err) {
      toast(err.message, 'error')
    }
  }

  const handleResendOtp = async () => {
    try {
      await api('/auth/resend-otp', { method: 'POST', body: { otpRequestId: otpData.otpRequestId } })
      toast('OTP resent successfully', 'success')
    } catch (err) {
      toast(err.message, 'error')
    }
  }

  const handleVerifyClinicCode = async (e) => {
    e.preventDefault()
    if (!clinicCode.trim()) {
      toast('Please enter your clinic verification code', 'error')
      return
    }

    try {
      const data = await api('/patients/verify-clinic-code', {
        method: 'POST',
        body: { username: clinicCodeUsername, code: clinicCode.toUpperCase() },
      })

      if (data.ok && data.status === 'VERIFIED') {
        toast('Account verified successfully! Please login again.', 'success')
        setShowClinicCode(false)
        setClinicCode('')
        // Clear form to allow re-login
        setIdentifier('')
        setPassword('')
      } else {
        throw new Error(data.message || data.error || 'Verification failed')
      }
    } catch (err) {
      toast(err.message || 'Failed to verify clinic code', 'error')
    }
  }

  return (
    <div className="auth-container">
      <aside className="auth-sidebar">
        <div className="auth-sidebar-content">
          <div className="auth-sidebar-logo">
            <div className="medical-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div className="auth-sidebar-brand">
              <h2>CARECRYPT</h2>
              <p>Healthcare Security Platform</p>
            </div>
          </div>

          <div className="auth-sidebar-features">
            <div className="sidebar-feature">
              <div className="sidebar-feature-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 8V12L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <div className="sidebar-feature-text">
                <h4>Secure Access</h4>
                <p>Enterprise-grade authentication</p>
              </div>
            </div>
            <div className="sidebar-feature">
              <div className="sidebar-feature-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <div className="sidebar-feature-text">
                <h4>HIPAA Compliant</h4>
                <p>Full regulatory compliance</p>
              </div>
            </div>
            <div className="sidebar-feature">
              <div className="sidebar-feature-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <rect x="3" y="8" width="18" height="12" rx="2" stroke="currentColor" strokeWidth="2"/>
                  <path d="M3 10C3 8.89543 3.89543 8 5 8H19C20.1046 8 21 8.89543 21 10V18C21 19.1046 20.1046 20 19 20H5C3.89543 20 3 19.1046 3 18V10Z" stroke="currentColor" strokeWidth="2"/>
                  <path d="M7 8V6C7 4.34315 8.34315 3 10 3H14C15.6569 3 17 4.34315 17 6V8" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <div className="sidebar-feature-text">
                <h4>Data Protection</h4>
                <p>End-to-end encryption</p>
              </div>
            </div>
          </div>

          <div className="auth-sidebar-footer">
            <p>Trusted by healthcare professionals</p>
          </div>
        </div>
      </aside>

      <main className="auth-main">
        <div className="auth-main-content">
          <div className="auth-card">
            <div className="auth-card-header">
              <h1>Welcome Back</h1>
              <p>Sign in to your account to continue</p>
            </div>

            {showClinicCode ? (
              <div>
                <div className="auth-alert auth-alert-warning">
                  <div className="alert-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                      <path d="M12 8V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                      <path d="M12 16H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                  </div>
                  <div className="alert-content">
                    <strong>Account Verification Required</strong>
                    <p>Your account has been created but needs verification. Enter the clinic code provided by your healthcare provider.</p>
                  </div>
                </div>
                <form onSubmit={handleVerifyClinicCode} className="auth-form">
                  <div className="auth-form-group">
                    <label className="auth-form-label">Username</label>
                    <input
                      type="text"
                      className="auth-form-input"
                      value={clinicCodeUsername}
                      disabled
                    />
                  </div>
                  <div className="auth-form-group">
                    <label className="auth-form-label">Clinic Verification Code *</label>
                    <input
                      type="text"
                      className="auth-form-input"
                      value={clinicCode}
                      onChange={(e) => setClinicCode(e.target.value.toUpperCase())}
                      placeholder="ABC123"
                      required
                      style={{ textTransform: 'uppercase' }}
                    />
                    <small className="auth-form-hint">
                      Enter the verification code provided by your healthcare provider
                    </small>
                  </div>
                  <div className="auth-form-actions">
                    <button type="submit" className="auth-btn-primary">Verify Account</button>
                    <button type="button" onClick={() => { setShowClinicCode(false); setClinicCode('') }} className="auth-btn-secondary">Cancel</button>
                  </div>
                </form>
              </div>
            ) : !showOtp ? (
              <form onSubmit={handleLogin} className="auth-form">
                <div className="auth-form-group">
                  <label className="auth-form-label">Username or Email</label>
                  <input
                    type="text"
                    className="auth-form-input"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="Enter your username or email"
                    required
                  />
                </div>

                <div className="auth-form-group">
                  <label className="auth-form-label">Password</label>
                  <input
                    type="password"
                    className="auth-form-input"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    required
                  />
                </div>

                <div className="auth-form-group">
                  <label className="auth-form-label">MFA (optional)</label>
                  <input
                    type="text"
                    className="auth-form-input"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    placeholder="123456"
                  />
                  <small className="auth-form-hint">
                    If you enabled Email OTP MFA, leave this empty and you’ll get an OTP. Seeded demo staff accounts can use <strong>123456</strong>.
                  </small>
                </div>

                <button type="submit" className="auth-btn-primary">
                  Sign In
                </button>
              </form>
            ) : (
              <div>
                <div className="auth-alert auth-alert-info">
                  <div className="alert-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                      <path d="M12 8V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                      <path d="M12 16H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                  </div>
                  <div className="alert-content">
                    <strong>Email OTP Required</strong>
                    <p>Enter the 6-digit code sent to your email. (MVP: Check server terminal logs)</p>
                  </div>
                </div>
                <form onSubmit={handleOtpVerify} className="auth-form">
                  <div className="auth-form-group">
                    <label className="auth-form-label">OTP Code</label>
                    <input
                      type="text"
                      className="auth-form-input"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      placeholder="123456"
                      inputMode="numeric"
                      maxLength="6"
                      required
                    />
                  </div>

                  <div className="auth-form-checkbox">
                    <input
                      type="checkbox"
                      id="otp_remember"
                      checked={rememberDevice}
                      onChange={(e) => setRememberDevice(e.target.checked)}
                    />
                    <label htmlFor="otp_remember">Trust this device (skip OTP for 30 days)</label>
                  </div>

                  <div className="auth-form-actions">
                    <button type="submit" className="auth-btn-primary">Verify OTP</button>
                    <button type="button" onClick={handleResendOtp} className="auth-btn-secondary">Resend</button>
                  </div>

                  <div className="auth-otp-info">
                    <p>Expires: <span>{otpData?.expiresAt || '—'}</span></p>
                    <p>Sent to: <span>{otpData?.sentTo || '—'}</span></p>
                  </div>
                </form>
              </div>
            )}

            <div className="auth-divider">
              <span>or</span>
            </div>

            <div className="auth-link">
              <p>Don't have an account? <Link to="/signup">Sign Up</Link></p>
              <p className="auth-forgot-password"><Link to="/forgot-password">Forgot Password?</Link></p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
