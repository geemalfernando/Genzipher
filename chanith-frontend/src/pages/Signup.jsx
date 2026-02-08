import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast, getDeviceId } from '../utils/api'
import { base64UrlToUint8Array, arrayBufferToBytes } from '../utils/webauthn'

export default function Signup() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [selectedRole, setSelectedRole] = useState('pharmacy')
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    mfaCode: '',
  })
  const [loading, setLoading] = useState(false)
  const [biometricEnrolling, setBiometricEnrolling] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      let result

      if (selectedRole === 'pharmacy') {
        // Pharmacist registration
        result = await api('/pharmacist/signup', {
          method: 'POST',
          body: { ...formData, deviceId: getDeviceId() },
        })

        if (result.token) {
          login(result.token)
          toast('Account created successfully!', 'success')
          
          // Enroll biometric for pharmacist
          setBiometricEnrolling(true)
          try {
            await enrollBiometric(result.token)
            toast('Biometric enrolled successfully!', 'success')
            navigate('/dashboard')
          } catch (err) {
            console.error('Biometric enrollment error:', err)
            if (String(err?.message || '') === 'credential_exists') {
              toast('This device biometric is already enrolled on another pharmacy account. Login to that account, or enroll using a different device/browser.', 'warning')
            } else {
              toast('Account created but biometric enrollment failed. Please enroll later.', 'warning')
            }
            navigate('/dashboard')
          } finally {
            setBiometricEnrolling(false)
          }
        }
      } else if (selectedRole === 'patient') {
        // Patient registration
        result = await api('/patients/pre-register', {
          method: 'POST',
          body: {
            username: formData.username,
            password: formData.password,
            email: formData.email || undefined,
            mfaCode: formData.mfaCode,
            deviceId: getDeviceId(),
          },
        })

        if (result.patientId) {
          const parts = []
          parts.push('Account created.')
          if (result.accountStatus === 'PENDING_ADMIN_APPROVAL') {
            parts.push('Pending admin approval (you will receive an email when activated).')
          }
          if (result.status === 'PENDING' && result.verification?.required) {
            parts.push('Clinic verification required (check your email/console for the code).')
          }
          toast(parts.join(' '), result.accountStatus === 'PENDING_ADMIN_APPROVAL' ? 'warning' : 'success')
          navigate('/login')
        }
      } else if (selectedRole === 'doctor') {
        // Doctor registration (admin approval required)
        result = await api('/doctors/pre-register', {
          method: 'POST',
          body: {
            username: formData.username,
            password: formData.password,
            email: formData.email,
          },
        })
        if (result.ok) {
          toast('Doctor account created. Pending admin approval (you will receive an email when activated).', 'warning')
          navigate('/login')
        }
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

    const challengeBuffer = base64UrlToUint8Array(enrollmentOptions?.challenge)
    const userIdBuffer = base64UrlToUint8Array(enrollmentOptions?.user?.id)

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
      rawId: arrayBufferToBytes(credential.rawId),
      response: {
        attestationObject: arrayBufferToBytes(credential.response.attestationObject),
        clientDataJSON: arrayBufferToBytes(credential.response.clientDataJSON),
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
      // Enroll does not count as verified; the pharmacy session still requires a verify step.
      toast(result.alreadyEnrolled ? 'Biometric already enrolled. Please verify to continue.' : 'Biometric enrolled. Please verify to continue.', result.alreadyEnrolled ? 'warning' : 'success')
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
                <h4>Secure Registration</h4>
                <p>Enterprise-grade account creation</p>
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
                <h4>Role-Based Access</h4>
                <p>Choose your role and permissions</p>
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
              <h1>Create Account</h1>
              <p>Sign up to access the healthcare platform</p>
            </div>

            <form onSubmit={handleSubmit} className="auth-form">
              <div className="auth-form-group">
                <label className="auth-form-label">Select Role *</label>
                <div className="role-selector">
                  <button
                    type="button"
                    className={`role-option ${selectedRole === 'pharmacy' ? 'active' : ''}`}
                    onClick={() => setSelectedRole('pharmacy')}
                  >
                    <div className="role-icon">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
                      </svg>
                    </div>
                    <div className="role-info">
                      <div className="role-name">Pharmacist</div>
                      <div className="role-desc">Medicine management</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    className={`role-option ${selectedRole === 'doctor' ? 'active' : ''}`}
                    onClick={() => setSelectedRole('doctor')}
                  >
                    <div className="role-icon">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </div>
                    <div className="role-info">
                      <div className="role-name">Doctor</div>
                      <div className="role-desc">Prescription management</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    className={`role-option ${selectedRole === 'patient' ? 'active' : ''}`}
                    onClick={() => setSelectedRole('patient')}
                  >
                    <div className="role-icon">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M20 21V19C20 17.9391 19.5786 16.9217 18.8284 16.1716C18.0783 15.4214 17.0609 15 16 15H8C6.93913 15 5.92172 15.4214 5.17157 16.1716C4.42143 16.9217 4 17.9391 4 19V21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        <path d="M12 11C14.2091 11 16 9.20914 16 7C16 4.79086 14.2091 3 12 3C9.79086 3 8 4.79086 8 7C8 9.20914 9.79086 11 12 11Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </div>
                    <div className="role-info">
                      <div className="role-name">Patient</div>
                      <div className="role-desc">View health records</div>
                    </div>
                  </button>
                </div>
              </div>

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
                  placeholder="Enter your username"
                  required
                  maxLength={32}
                />
                <small className="auth-form-hint">
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
                  placeholder="Enter your email"
                  required={selectedRole !== 'patient'}
                />
                {selectedRole === 'patient' && (
                  <small className="auth-form-hint">
                    Optional for patients
                  </small>
                )}
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
                <small className="auth-form-hint">
                  Minimum 8 characters
                </small>
              </div>

              {(selectedRole === 'pharmacy' || selectedRole === 'doctor' || selectedRole === 'patient') && (
                <div className="auth-form-group">
                  <label className="auth-form-label">Registration Code *</label>
                  <input
                    type="text"
                    className="auth-form-input"
                    value={formData.mfaCode}
                    onChange={(e) => setFormData({ ...formData, mfaCode: e.target.value })}
                    placeholder="123456"
                    required
                    maxLength="6"
                  />
                  <small className="auth-form-hint">
                    This is only for account creation (admin-issued in production). After signup, MFA is per-user Email OTP.
                  </small>
                </div>
              )}

              {selectedRole === 'pharmacy' && (
                <div className="auth-alert auth-alert-info">
                  <div className="alert-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                      <path d="M12 8V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                      <path d="M12 16H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                  </div>
                  <div className="alert-content">
                    <strong>Biometric Enrollment Required</strong>
                    <p>After account creation, you'll be prompted to enroll your biometric (fingerprint/face) for secure access.</p>
                  </div>
                </div>
              )}

              <button 
                type="submit" 
                className="auth-btn-primary" 
                disabled={loading || biometricEnrolling}
              >
                {biometricEnrolling 
                  ? 'Enrolling Biometric...' 
                  : loading 
                    ? 'Creating Account...' 
                    : 'Create Account'
                }
              </button>
            </form>

            <div className="auth-divider">
              <span>or</span>
            </div>

            <div className="auth-link">
              <p>Already have an account? <Link to="/login">Sign In</Link></p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
