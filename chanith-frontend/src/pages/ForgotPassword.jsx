import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { api, toast } from '../utils/api'

export default function ForgotPassword() {
  const navigate = useNavigate()
  const [identifier, setIdentifier] = useState('')
  const [otp, setOtp] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [otpRequestId, setOtpRequestId] = useState(null)
  const [otpData, setOtpData] = useState(null)
  const [remainingAttempts, setRemainingAttempts] = useState(3)
  const [loading, setLoading] = useState(false)
  const [step, setStep] = useState('request') // 'request', 'verify', 'reset'
  const [resetToken, setResetToken] = useState(null)

  const handleSendCode = async (e) => {
    e.preventDefault()
    if (!identifier.trim()) {
      toast('Please enter your username or email', 'error')
      return
    }

    try {
      setLoading(true)
      // Request password reset OTP
      const data = await api('/auth/forgot-password/request', {
        method: 'POST',
        body: { identifier },
      })

      if (data.otpRequestId) {
        setOtpRequestId(data.otpRequestId)
        setOtpData(data)
        setRemainingAttempts(3)
        setStep('verify')
        toast('OTP code sent to your email', 'success')
      } else {
        throw new Error(data.message || data.error || 'Failed to send OTP')
      }
    } catch (err) {
      console.error('Send code error:', err)
      let errorMessage = err.message
      if (err.message.includes('fetch') || err.message.includes('NetworkError')) {
        errorMessage = 'Cannot connect to server. Please make sure the backend is running.'
      }
      toast(errorMessage || 'Failed to send reset code. Please try again.', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyOtp = async (e) => {
    e.preventDefault()
    if (!otp || otp.length !== 6) {
      toast('Please enter a valid 6-digit OTP code', 'error')
      return
    }

    try {
      setLoading(true)
      const data = await api('/auth/forgot-password/verify-otp', {
        method: 'POST',
        body: { otpRequestId, otp },
      })

      if (data.resetToken) {
        setResetToken(data.resetToken)
        setStep('reset')
        toast('OTP verified successfully. Please enter your new password.', 'success')
      } else {
        throw new Error(data.message || data.error || 'OTP verification failed')
      }
    } catch (err) {
      console.error('Verify OTP error:', err)
      const rem = err?.data?.remainingAttempts
      if (typeof rem === 'number') {
        setRemainingAttempts(rem)
        if (rem <= 0) {
          toast('Too many wrong OTP attempts. Please contact admin approval.', 'error')
          setStep('request')
          setOtpRequestId(null)
          setOtp('')
          return
        }
        toast(`Invalid OTP. ${rem} attempts remaining.`, 'error')
        return
      }
      toast(err.message || 'Failed to verify OTP', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleResetPassword = async (e) => {
    e.preventDefault()
    if (!newPassword || newPassword.length < 8) {
      toast('Password must be at least 8 characters', 'error')
      return
    }
    if (newPassword !== confirmPassword) {
      toast('Passwords do not match', 'error')
      return
    }

    try {
      setLoading(true)
      const data = await api('/auth/forgot-password/set-password', {
        method: 'POST',
        body: { resetToken, newPassword },
      })

      if (data.ok) {
        toast('Password reset successfully! Redirecting to login...', 'success')
        setTimeout(() => {
          navigate('/login')
        }, 2000)
      } else {
        throw new Error(data.message || data.error || 'Failed to reset password')
      }
    } catch (err) {
      console.error('Reset password error:', err)
      toast(err.message || 'Failed to reset password. Please try again.', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleResendOtp = async () => {
    try {
      setLoading(true)
      const data = await api('/auth/resend-otp', { method: 'POST', body: { otpRequestId } })
      toast(`OTP resent (${data.delivery || 'email'})`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to resend OTP. Please try again.', 'error')
    } finally {
      setLoading(false)
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
                <h4>Secure Reset</h4>
                <p>Email OTP verification</p>
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
                <h4>Account Recovery</h4>
                <p>Safe password reset process</p>
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
                <p>Secure account management</p>
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
              <h1>Reset password (Email OTP)</h1>
              <p>Enter your username/email. We'll send a 6-digit code to your email if the account has one.</p>
            </div>

            {step === 'request' && (
              <form onSubmit={handleSendCode} className="auth-form">
                <div className="auth-form-group">
                  <label className="auth-form-label">Username or email</label>
                  <input
                    type="text"
                    className="auth-form-input"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="Enter your username or email"
                    required
                  />
                </div>

                <button type="submit" className="auth-btn-primary" disabled={loading}>
                  {loading ? 'Sending...' : 'Send code'}
                </button>
              </form>
            )}

            {step === 'verify' && (
              <form onSubmit={handleVerifyOtp} className="auth-form">
                <div className="auth-form-group">
                  <label className="auth-form-label">OTP</label>
                  <input
                    type="text"
                    className="auth-form-input"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="123456"
                    inputMode="numeric"
                    maxLength="6"
                    required
                  />
                  <small className="auth-form-hint">
                    Enter the 6-digit code sent to your email
                  </small>
                </div>

                <div style={{ 
                  marginBottom: '1.5rem', 
                  fontSize: '0.875rem', 
                  color: 'var(--healthcare-text-muted)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <span>Remaining attempts: <strong>{remainingAttempts}</strong></span>
                </div>

                <div className="auth-form-actions">
                  <button type="submit" className="auth-btn-primary" disabled={loading || remainingAttempts <= 0}>
                    {loading ? 'Verifying...' : 'Verify OTP'}
                  </button>
                  <button type="button" onClick={handleResendOtp} className="auth-btn-secondary" disabled={loading}>
                    Resend
                  </button>
                </div>

                {otpRequestId && (
                  <div style={{ marginTop: '1rem', fontSize: '0.75rem', color: 'var(--healthcare-text-muted)', fontFamily: 'monospace' }}>
                    otpRequestId: {otpRequestId}
                  </div>
                )}
              </form>
            )}

            {step === 'reset' && (
              <form onSubmit={handleResetPassword} className="auth-form">
                <div className="auth-form-group">
                  <label className="auth-form-label">New Password</label>
                  <input
                    type="password"
                    className="auth-form-input"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter your new password"
                    required
                    minLength="8"
                  />
                  <small className="auth-form-hint">
                    Minimum 8 characters
                  </small>
                </div>

                <div className="auth-form-group">
                  <label className="auth-form-label">Confirm New Password</label>
                  <input
                    type="password"
                    className="auth-form-input"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm your new password"
                    required
                    minLength="8"
                  />
                </div>

                <button type="submit" className="auth-btn-primary" disabled={loading}>
                  {loading ? 'Resetting...' : 'Reset Password'}
                </button>
              </form>
            )}

            <div className="auth-divider">
              <span>or</span>
            </div>

            <div className="auth-link">
              <p>Remember your password? <Link to="/login">Sign In</Link></p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
