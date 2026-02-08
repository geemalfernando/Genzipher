import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import TotpSetupCard from '../components/TotpSetupCard'
import '../styles/PatientDashboard.css'

export default function ManufacturerDashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [user, setUser] = useState(null)
  
  // Batch management
  const [batches, setBatches] = useState([])
  const [batchForm, setBatchForm] = useState({
    batchId: '',
    lot: '',
    expiry: '',
    certificateHash: ''
  })
  const [verificationResult, setVerificationResult] = useState(null)

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    loadUserData()
  }, [token, navigate])

  const loadUserData = async () => {
    try {
      const data = await api('/me')
      setUser(data.user)
    } catch (err) {
      toast(err.message, 'error')
      if (err.message.includes('unauthorized') || err.message.includes('token')) {
        logout()
        navigate('/login')
      }
    }
  }

  const handleRegisterBatch = async (e) => {
    e.preventDefault()
    if (!batchForm.batchId || !batchForm.lot || !batchForm.expiry || !batchForm.certificateHash) {
      toast('All fields are required', 'error')
      return
    }

    try {
      setLoading(true)
      const result = await api('/batches', {
        method: 'POST',
        body: batchForm
      })
      
      toast('Batch Secured & Signed ✓', 'success')
      setBatchForm({ batchId: '', lot: '', expiry: '', certificateHash: '' })
      setBatches([result, ...batches])
    } catch (err) {
      toast(err.message || 'Failed to register batch', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyBatch = async (e) => {
    e.preventDefault()
    const batchJson = e.target.batchJson.value
    if (!batchJson) {
      toast('Please paste batch JSON', 'error')
      return
    }

    try {
      setLoading(true)
      let batch
      try {
        batch = JSON.parse(batchJson)
      } catch {
        throw new Error('Invalid JSON format')
      }

      const result = await api('/batches/verify', {
        method: 'POST',
        body: { batch }
      })
      
      setVerificationResult(result)
      if (result.ok && result.signatureOk && !result.expired) {
        toast('Verified ✓', 'success')
      } else {
        toast('Verification failed ✗', 'error')
      }
    } catch (err) {
      toast(err.message || 'Failed to verify batch', 'error')
      setVerificationResult(null)
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

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
            <p>Manufacturer Portal</p>
          </div>
        </div>

        <nav className="patient-sidebar-nav">
          <button className="nav-item active">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Batch Management</span>
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
              <h1>Manufacturer Dashboard</h1>
              <p style={{ color: 'var(--healthcare-text-muted)', marginTop: '0.5rem' }}>
                Welcome, {user?.username || 'Manufacturer'} - Register and verify medicine batches
              </p>
            </div>

            <div className="section-grid">
              {user && (!user.mfaEnabled || user.mfaMethod === 'NONE') && (
                <TotpSetupCard title="MFA: Authenticator app (recommended)" onEnabled={loadUserData} />
              )}

              <div className="healthcare-card">
                <h2>Register New Batch</h2>
                <p style={{ color: 'var(--healthcare-text-muted)', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
                  Register a new medicine batch. It will be secured and signed to prevent tampering.
                </p>
                <form onSubmit={handleRegisterBatch} className="appointment-form">
                  <div className="form-group">
                    <label>Batch ID *</label>
                    <input
                      type="text"
                      value={batchForm.batchId}
                      onChange={(e) => setBatchForm({ ...batchForm, batchId: e.target.value })}
                      placeholder="BATCH-001"
                      required
                      className="form-input"
                    />
                  </div>
                  <div className="form-group">
                    <label>Lot Number *</label>
                    <input
                      type="text"
                      value={batchForm.lot}
                      onChange={(e) => setBatchForm({ ...batchForm, lot: e.target.value })}
                      placeholder="LOT-2024-001"
                      required
                      className="form-input"
                    />
                  </div>
                  <div className="form-group">
                    <label>Expiry Date *</label>
                    <input
                      type="date"
                      value={batchForm.expiry}
                      onChange={(e) => setBatchForm({ ...batchForm, expiry: e.target.value })}
                      required
                      className="form-input"
                    />
                  </div>
                  <div className="form-group">
                    <label>Certificate Hash *</label>
                    <input
                      type="text"
                      value={batchForm.certificateHash}
                      onChange={(e) => setBatchForm({ ...batchForm, certificateHash: e.target.value })}
                      placeholder="Certificate hash"
                      required
                      className="form-input"
                    />
                    <small style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                      Integrity proof for the batch certificate document
                    </small>
                  </div>
                  <button type="submit" className="btn-primary" disabled={loading}>
                    {loading ? 'Registering...' : 'Register Batch'}
                  </button>
                </form>
              </div>

              <div className="healthcare-card">
                <h2>Verify Batch</h2>
                <p style={{ color: 'var(--healthcare-text-muted)', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
                  Verify the batch (signature + expiry) before it can be dispensed.
                </p>
                <form onSubmit={handleVerifyBatch} className="appointment-form">
                  <div className="form-group">
                    <label>Batch JSON *</label>
                    <textarea
                      name="batchJson"
                      placeholder='{"batchId": "BATCH-001", "manufacturerId": "...", "signatureB64url": "...", ...}'
                      rows="8"
                      required
                      className="form-input"
                      style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}
                    />
                    <small style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                      Paste the complete batch JSON object
                    </small>
                  </div>
                  <button type="submit" className="btn-primary" disabled={loading}>
                    {loading ? 'Verifying...' : 'Verify Batch'}
                  </button>
                </form>

                {verificationResult && (
                  <div style={{ marginTop: '1.5rem', padding: '1rem', background: verificationResult.ok && verificationResult.signatureOk && !verificationResult.expired ? 'var(--healthcare-success-bg)' : 'var(--healthcare-error-bg)', borderRadius: '8px' }}>
                    <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Verification Result</h3>
                    <div style={{ fontSize: '0.875rem' }}>
                      <p><strong>Valid:</strong> {verificationResult.ok ? '✓ Yes' : '✗ No'}</p>
                      <p><strong>Signature:</strong> {verificationResult.signatureOk ? '✓ Valid' : '✗ Invalid'}</p>
                      <p><strong>Expired:</strong> {verificationResult.expired ? '✗ Yes' : '✓ No'}</p>
                      {verificationResult.error && <p><strong>Error:</strong> {verificationResult.error}</p>}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
