import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import '../styles/PatientDashboard.css'

export default function PharmacistDashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [activeTab, setActiveTab] = useState('dashboard')
  const [loading, setLoading] = useState(true)
  const [biometricVerified, setBiometricVerified] = useState(false)
  const [biometricEnrolled, setBiometricEnrolled] = useState(false)
  const [biometricError, setBiometricError] = useState(null)
  const [user, setUser] = useState(null)
  
  // Dashboard statistics
  const [statistics, setStatistics] = useState({
    totalMedicines: 0,
    totalStockItems: 0,
    lowStockItems: 0,
    expiredItems: 0,
    pendingVerifications: 0
  })

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    checkBiometricStatus()
  }, [token, navigate])

  const checkBiometricStatus = async () => {
    try {
      setLoading(true)
      const [userData, biometricStatus] = await Promise.all([
        api('/demo/whoami'),
        api('/pharmacy/biometric-status')
      ])
      
      setUser(userData.auth)
      setBiometricEnrolled(userData.auth?.biometricEnrolled || false)
      setBiometricVerified(biometricStatus.biometricVerified || false)
      
      if (biometricStatus.biometricVerified) {
        loadDashboard()
      }
    } catch (err) {
      console.error('Biometric status check error:', err)
      setBiometricError(err.message || 'Failed to check biometric status')
    } finally {
      setLoading(false)
    }
  }

  const loadDashboard = async () => {
    try {
      const data = await api('/pharmacy/dashboard')
      setStatistics(data.statistics || statistics)
    } catch (err) {
      console.error('Dashboard load error:', err)
    }
  }

  const handleEnrollBiometric = async () => {
    if (!window.PublicKeyCredential) {
      setBiometricError('WebAuthn is not supported in this browser.')
      return
    }

    try {
      setBiometricError(null)
      
      // Start enrollment
      const enrollmentOptions = await api('/biometric/enroll/start', {
        method: 'POST'
      })

      const challengeBuffer = Uint8Array.from(
        atob(enrollmentOptions.challenge.replace(/-/g, '+').replace(/_/g, '/')), 
        c => c.charCodeAt(0)
      )
      const userIdBuffer = Uint8Array.from(
        atob(enrollmentOptions.user.id.replace(/-/g, '+').replace(/_/g, '/')), 
        c => c.charCodeAt(0)
      )

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
        body: {
          credential: credentialForServer,
          challenge: enrollmentOptions.challenge,
          deviceName: 'Primary Device',
        },
      })

      if (result.ok) {
        setBiometricEnrolled(true)
        setBiometricVerified(false)
        toast(result.alreadyEnrolled ? 'Biometric already enrolled on this account. Please verify to continue.' : 'Biometric enrolled. Please verify to continue.', result.alreadyEnrolled ? 'warning' : 'success')
        await checkBiometricStatus()
      }
    } catch (err) {
      console.error('Biometric enrollment error:', err)
      setBiometricError(err.message || 'Biometric enrollment failed')
      if (String(err?.message || '') === 'credential_exists') {
        toast('This device biometric is already enrolled on another pharmacy account. Login to that account, or enroll using a different device/browser.', 'warning')
      } else {
        toast(err.message || 'Biometric enrollment failed', 'error')
      }
    }
  }

  const handleVerifyBiometric = async () => {
    if (!window.PublicKeyCredential) {
      setBiometricError('WebAuthn is not supported in this browser.')
      return
    }

    try {
      setBiometricError(null)
      
      // Start verification
      const verifyOptions = await api('/biometric/verify/start', {
        method: 'POST'
      })

      if (!verifyOptions?.challenge || !Array.isArray(verifyOptions?.allowCredentials)) {
        throw new Error('internal_error')
      }

      const challengeBuffer = Uint8Array.from(
        atob(verifyOptions.challenge.replace(/-/g, '+').replace(/_/g, '/')), 
        c => c.charCodeAt(0)
      )

      const publicKeyCredentialRequestOptions = {
        challenge: challengeBuffer,
        allowCredentials: verifyOptions.allowCredentials.map(cred => ({
          ...cred,
          id: Uint8Array.from(atob(String(cred.id || '').replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
        })),
        timeout: verifyOptions.timeout,
        rpId: verifyOptions.rpId,
        userVerification: verifyOptions.userVerification,
      }

      toast('Please scan your fingerprint or face when prompted...', 'info')

      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
      })

      const assertionForServer = {
        id: assertion.id,
        rawId: Array.from(new Uint8Array(assertion.rawId)),
        response: {
          authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
          clientDataJSON: Array.from(new Uint8Array(assertion.response.clientDataJSON)),
          signature: Array.from(new Uint8Array(assertion.response.signature)),
          userHandle: assertion.response.userHandle ? Array.from(new Uint8Array(assertion.response.userHandle)) : null,
        },
        type: assertion.type,
      }

      const result = await api('/biometric/verify/complete', {
        method: 'POST',
        body: {
          credential: assertionForServer,
          challenge: verifyOptions.challenge,
        },
      })

      if (result.ok) {
        setBiometricVerified(true)
        toast('Biometric verified successfully!', 'success')
        loadDashboard()
      }
    } catch (err) {
      console.error('Biometric verification error:', err)
      setBiometricError(err.message || 'Biometric verification failed')
      toast(err.message || 'Biometric verification failed', 'error')
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  if (loading) {
    return (
      <div className="patient-dashboard">
        <div className="loading-state">
          <p>Loading...</p>
        </div>
      </div>
    )
  }

  // Show biometric verification if not verified
  if (!biometricVerified) {
    return (
      <div className="patient-dashboard">
        <aside className="patient-sidebar">
          <div className="patient-sidebar-header">
            <div className="medical-icon">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div className="sidebar-brand">
              <h2>CARECRYPT</h2>
              <p>Pharmacy Portal</p>
            </div>
          </div>
          <div className="patient-sidebar-footer">
            <button onClick={handleLogout} className="logout-btn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M9 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V5C3 4.46957 3.21071 3.96086 3.58579 3.58579C3.96086 3.21071 4.46957 3 5 3H9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M16 17L21 12L16 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M21 12H9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span>Logout</span>
            </button>
          </div>
        </aside>

        <main className="patient-main">
          <div className="patient-content">
            <div className="dashboard-section">
              <div className="healthcare-card">
                <h2>Biometric Verification Required</h2>
                <p style={{ marginBottom: '2rem', color: 'var(--healthcare-text-muted)' }}>
                  Please complete biometric verification to access the pharmacy dashboard.
                </p>

                {biometricError && (
                  <div className="auth-alert auth-alert-error" style={{ marginBottom: '1.5rem' }}>
                    <div className="alert-icon">✕</div>
                    <div className="alert-content">
                      <strong>Error: {biometricError}</strong>
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                  {!biometricEnrolled ? (
                    <button onClick={handleEnrollBiometric} className="btn-primary">
                      Enroll Biometric
                    </button>
                  ) : (
                    <button onClick={handleVerifyBiometric} className="btn-primary">
                      Start Biometric Verification
                    </button>
                  )}
                </div>

                <div style={{ marginTop: '2rem', padding: '1rem', background: 'var(--healthcare-bg)', borderRadius: '8px' }}>
                  <p style={{ fontSize: '0.875rem', color: 'var(--healthcare-text-muted)', margin: 0 }}>
                    <strong>Note:</strong> This will use your device's fingerprint scanner or face recognition. Make sure your browser has permission to access biometrics.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    )
  }

  // Main dashboard after biometric verification
  return (
    <div className="patient-dashboard">
      <aside className="patient-sidebar">
        <div className="patient-sidebar-header">
          <div className="medical-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div className="sidebar-brand">
            <h2>CARECRYPT</h2>
            <p>Pharmacy Portal</p>
          </div>
        </div>

        <nav className="patient-sidebar-nav">
          <button 
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M3 9L12 2L21 9V20C21 20.5304 20.7893 21.0391 20.4142 21.4142C20.0391 21.7893 19.5304 22 19 22H5C4.46957 22 3.96086 21.7893 3.58579 21.4142C3.21071 21.0391 3 20.5304 3 20V9Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M9 22V12H15V22" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Dashboard</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'medicines' ? 'active' : ''}`}
            onClick={() => setActiveTab('medicines')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Medicines</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'stock' ? 'active' : ''}`}
            onClick={() => setActiveTab('stock')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M18 8H6C4.89543 8 4 8.89543 4 10V20C4 21.1046 4.89543 22 6 22H18C19.1046 22 20 21.1046 20 20V10C20 8.89543 19.1046 8 18 8Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M10 4H14C14.5304 4 15.0391 4.21071 15.4142 4.58579C15.7893 4.96086 16 5.46957 16 6V8H8V6C8 5.46957 8.21071 4.96086 8.58579 4.58579C8.96086 4.21071 9.46957 4 10 4Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Stock</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'quality' ? 'active' : ''}`}
            onClick={() => setActiveTab('quality')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Quality</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'dispense' ? 'active' : ''}`}
            onClick={() => setActiveTab('dispense')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M8 2V6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M16 2V6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M3 10H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M19 4H5C3.89543 4 3 4.89543 3 6V20C3 21.1046 3.89543 22 5 22H19C20.1046 22 21 21.1046 21 20V6C21 4.89543 20.1046 4 19 4Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Dispense</span>
          </button>
        </nav>

        <div className="patient-sidebar-footer">
          <button onClick={handleLogout} className="logout-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M9 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V5C3 4.46957 3.21071 3.96086 3.58579 3.58579C3.96086 3.21071 4.46957 3 5 3H9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M16 17L21 12L16 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M21 12H9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span>Logout</span>
          </button>
        </div>
      </aside>

      <main className="patient-main">
        <div className="patient-content">
          <div className="dashboard-section">
            <div className="section-header">
              <div>
                <h1>Role Workspace</h1>
                <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.9375rem' }}>
                  Current role: {user?.role || 'pharmacy'}
                </p>
              </div>
            </div>

            {activeTab === 'dashboard' && (
              <div>
                <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                    <h2>Pharmacist Dashboard</h2>
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <button onClick={loadDashboard} className="btn-primary" style={{ whiteSpace: 'nowrap' }}>
                        Refresh Dashboard
                      </button>
                    </div>
                  </div>

                  <div style={{ marginBottom: '2rem' }}>
                    <h3 style={{ marginBottom: '1rem', fontSize: '1.25rem', fontWeight: 600 }}>Statistics</h3>
                    <div className="section-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
                      <div className="healthcare-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
                        <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--healthcare-primary)', marginBottom: '0.5rem' }}>
                          {statistics.totalMedicines}
                        </div>
                        <div style={{ fontSize: '0.9375rem', color: 'var(--healthcare-text-muted)', fontWeight: 500 }}>
                          Total Medicines
                        </div>
                      </div>
                      <div className="healthcare-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
                        <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--healthcare-primary)', marginBottom: '0.5rem' }}>
                          {statistics.totalStockItems}
                        </div>
                        <div style={{ fontSize: '0.9375rem', color: 'var(--healthcare-text-muted)', fontWeight: 500 }}>
                          Stock Items
                        </div>
                      </div>
                      <div className="healthcare-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
                        <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--healthcare-warning)', marginBottom: '0.5rem' }}>
                          {statistics.lowStockItems}
                        </div>
                        <div style={{ fontSize: '0.9375rem', color: 'var(--healthcare-text-muted)', fontWeight: 500 }}>
                          Low Stock
                        </div>
                      </div>
                      <div className="healthcare-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
                        <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--healthcare-danger)', marginBottom: '0.5rem' }}>
                          {statistics.expiredItems}
                        </div>
                        <div style={{ fontSize: '0.9375rem', color: 'var(--healthcare-text-muted)', fontWeight: 500 }}>
                          Expired Items
                        </div>
                      </div>
                      <div className="healthcare-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
                        <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--healthcare-primary)', marginBottom: '0.5rem' }}>
                          {statistics.pendingVerifications}
                        </div>
                        <div style={{ fontSize: '0.9375rem', color: 'var(--healthcare-text-muted)', fontWeight: 500 }}>
                          Pending Verifications
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'medicines' && (
              <div className="healthcare-card">
                <h2>Medicines Management</h2>
                <p style={{ color: 'var(--healthcare-text-muted)' }}>Medicine management functionality will be implemented here.</p>
              </div>
            )}

            {activeTab === 'stock' && (
              <div className="healthcare-card">
                <h2>Stock Management</h2>
                <p style={{ color: 'var(--healthcare-text-muted)' }}>Stock management functionality will be implemented here.</p>
              </div>
            )}

            {activeTab === 'quality' && (
              <div className="healthcare-card">
                <h2>Quality Verification</h2>
                <p style={{ color: 'var(--healthcare-text-muted)' }}>Quality verification functionality will be implemented here.</p>
              </div>
            )}

            {activeTab === 'dispense' && (
              <div className="healthcare-card">
                <h2>Dispense Management</h2>
                <p style={{ color: 'var(--healthcare-text-muted)' }}>Dispense management functionality will be implemented here.</p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
