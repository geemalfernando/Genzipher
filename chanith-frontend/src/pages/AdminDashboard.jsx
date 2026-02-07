import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import '../styles/PatientDashboard.css'

export default function AdminDashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [user, setUser] = useState(null)

  // User Activity (Audit Logs)
  const [userActivity, setUserActivity] = useState({
    user: '',
    actionFilter: ''
  })
  const [auditLogs, setAuditLogs] = useState([])
  const [auditLogsJson, setAuditLogsJson] = useState(null)

  // Verify Patients
  const [pendingPatients, setPendingPatients] = useState([])
  const [selectedPatientId, setSelectedPatientId] = useState('')

  // Clinic Code Generation
  const [clinicCodeData, setClinicCodeData] = useState({
    patientId: '',
    expiresMinutes: '10'
  })
  const [sendEmail, setSendEmail] = useState(true)
  const [generatedCode, setGeneratedCode] = useState(null)

  // SMTP Test
  const [smtpStatus, setSmtpStatus] = useState(null)
  const [testEmailTo, setTestEmailTo] = useState('you@example.com')

  // System Audit
  const [systemAuditLogs, setSystemAuditLogs] = useState([])
  const [systemAuditJson, setSystemAuditJson] = useState(null)

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    loadUserData()
    loadSmtpStatus()
  }, [token, navigate])

  const loadUserData = async () => {
    try {
      const data = await api('/demo/whoami')
      setUser(data.auth)
    } catch (err) {
      toast(err.message, 'error')
      if (err.message.includes('unauthorized') || err.message.includes('token')) {
        logout()
        navigate('/login')
      }
    }
  }

  const loadSmtpStatus = async () => {
    try {
      const data = await api('/admin/mail/status')
      setSmtpStatus(data.ok ? 'Connected' : (data.error || 'Not configured'))
    } catch (err) {
      setSmtpStatus('Error checking status')
    }
  }

  const handleLoadUserActivityLogs = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (userActivity.user) {
        // Try to extract username from format "username (role)" or just username
        const match = userActivity.user.match(/^(.+?)\s*\(/);
        const username = match ? match[1] : userActivity.user;
        params.append('username', username.trim())
      }
      if (userActivity.actionFilter) {
        params.append('action', userActivity.actionFilter.trim())
      }

      const data = await api(`/audit/logs?${params.toString()}`)
      setAuditLogs(data.entries || [])
      setAuditLogsJson(data)
      toast(`Loaded ${data.count || 0} audit log entries`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to load audit logs', 'error')
      setAuditLogs([])
    } finally {
      setLoading(false)
    }
  }

  const handleShowUserActivityJson = () => {
    if (auditLogsJson) {
      alert(JSON.stringify(auditLogsJson, null, 2))
    } else {
      toast('Please load logs first', 'warning')
    }
  }

  const handleCopyUserActivityJson = async () => {
    if (auditLogsJson) {
      try {
        await navigator.clipboard.writeText(JSON.stringify(auditLogsJson, null, 2))
        toast('JSON copied to clipboard', 'success')
      } catch (err) {
        toast('Failed to copy JSON', 'error')
      }
    } else {
      toast('Please load logs first', 'warning')
    }
  }

  const handleLoadPendingPatients = async () => {
    try {
      setLoading(true)
      const data = await api('/admin/patients?status=PENDING')
      setPendingPatients(data.patients || [])
      toast(`Loaded ${data.count || 0} pending patients`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to load pending patients', 'error')
      setPendingPatients([])
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateClinicCode = async () => {
    try {
      setLoading(true)
      const data = await api('/clinic/codes', {
        method: 'POST',
        body: {
          patientId: clinicCodeData.patientId || null,
          expiresMinutes: Number(clinicCodeData.expiresMinutes) || 10,
          sendEmail: sendEmail
        }
      })
      setGeneratedCode(data)
      toast('Clinic code generated successfully!', 'success')
    } catch (err) {
      toast(err.message || 'Failed to generate clinic code', 'error')
      setGeneratedCode(null)
    } finally {
      setLoading(false)
    }
  }

  const handleCopyGeneratedCode = async () => {
    if (generatedCode?.code) {
      try {
        await navigator.clipboard.writeText(generatedCode.code)
        toast('Code copied to clipboard', 'success')
      } catch (err) {
        toast('Failed to copy code', 'error')
      }
    }
  }

  const handleVerifySmtp = async () => {
    try {
      setLoading(true)
      const data = await api('/admin/mail/status')
      setSmtpStatus(data.ok ? 'Connected' : (data.error || 'Not configured'))
      if (data.ok) {
        toast('SMTP connection verified successfully', 'success')
      } else {
        toast(`SMTP error: ${data.error || 'Not configured'}`, 'error')
      }
    } catch (err) {
      setSmtpStatus('Error checking status')
      toast(err.message || 'Failed to verify SMTP', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleSendTestEmail = async () => {
    try {
      setLoading(true)
      await api('/admin/mail/test', {
        method: 'POST',
        body: { to: testEmailTo }
      })
      toast('Test email sent successfully!', 'success')
    } catch (err) {
      toast(err.message || 'Failed to send test email', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleLoadSystemAudit = async () => {
    try {
      setLoading(true)
      const data = await api('/audit/logs?limit=200')
      setSystemAuditLogs(data.entries || [])
      setSystemAuditJson(data)
      toast(`Loaded ${data.count || 0} system audit entries`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to load system audit', 'error')
      setSystemAuditLogs([])
    } finally {
      setLoading(false)
    }
  }

  const handleShowSystemAuditJson = () => {
    if (systemAuditJson) {
      alert(JSON.stringify(systemAuditJson, null, 2))
    } else {
      toast('Please load audit logs first', 'warning')
    }
  }

  const handleCopySystemAuditJson = async () => {
    if (systemAuditJson) {
      try {
        await navigator.clipboard.writeText(JSON.stringify(systemAuditJson, null, 2))
        toast('JSON copied to clipboard', 'success')
      } catch (err) {
        toast('Failed to copy JSON', 'error')
      }
    } else {
      toast('Please load audit logs first', 'warning')
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
            <p>Admin Portal</p>
          </div>
        </div>

        <nav className="patient-sidebar-nav">
          <div className="nav-item active">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M3 9L12 2L21 9V20C21 20.5304 20.7893 21.0391 20.4142 21.4142C20.0391 21.7893 19.5304 22 19 22H5C4.46957 22 3.96086 21.7893 3.58579 21.4142C3.21071 21.0391 3 20.5304 3 20V9Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M9 22V12H15V22" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Dashboard</span>
          </div>
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
                  Current role: {user?.role || 'admin'}
                </p>
              </div>
            </div>

            <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: 600 }}>
                Admin/Compliance: Audit Log
              </h2>

              {/* User Activity Section */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>User activity:</h3>
                <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">User</label>
                    <input
                      type="text"
                      className="form-input"
                      value={userActivity.user}
                      onChange={(e) => setUserActivity({ ...userActivity, user: e.target.value })}
                      placeholder="doctor1 (doctor)"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Action filter (optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={userActivity.actionFilter}
                      onChange={(e) => setUserActivity({ ...userActivity, actionFilter: e.target.value })}
                      placeholder="auth.login_failed"
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button onClick={handleLoadUserActivityLogs} className="btn-primary" disabled={loading}>
                    Load logs
                  </button>
                  <button onClick={handleShowUserActivityJson} className="btn-secondary">
                    Show JSON
                  </button>
                  <button onClick={handleCopyUserActivityJson} className="btn-secondary">
                    Copy JSON
                  </button>
                </div>
                {auditLogs.length > 0 && (
                  <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                    Loaded {auditLogs.length} log entries
                  </div>
                )}
              </div>

              {/* Verify Patients Section */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>Verify patients (clinic code):</h3>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', marginBottom: '1rem' }}>
                  <div className="form-group" style={{ flex: 1 }}>
                    <label className="form-label">Pending patients</label>
                    <select
                      className="form-input"
                      value={selectedPatientId}
                      onChange={(e) => {
                        setSelectedPatientId(e.target.value)
                        setClinicCodeData({ ...clinicCodeData, patientId: e.target.value })
                      }}
                    >
                      <option value="">Select a patient...</option>
                      {pendingPatients.map(patient => (
                        <option key={patient.patientId} value={patient.patientId}>
                          {patient.user?.username || patient.patientId} ({patient.status})
                        </option>
                      ))}
                    </select>
                  </div>
                  <button onClick={handleLoadPendingPatients} className="btn-secondary" disabled={loading}>
                    Refresh list
                  </button>
                </div>
              </div>

              {/* Bind to Patient ID Section */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>Bind to patientid:</h3>
                <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Bind to patientid</label>
                    <input
                      type="text"
                      className="form-input"
                      value={clinicCodeData.patientId}
                      onChange={(e) => setClinicCodeData({ ...clinicCodeData, patientId: e.target.value })}
                      placeholder="u_patient_..."
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Expires (minutes)</label>
                    <input
                      type="number"
                      className="form-input"
                      value={clinicCodeData.expiresMinutes}
                      onChange={(e) => setClinicCodeData({ ...clinicCodeData, expiresMinutes: e.target.value })}
                      placeholder="10"
                      min="1"
                    />
                  </div>
                </div>
              </div>

              {/* Delivery Section */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>Delivery:</h3>
                <div className="form-group" style={{ marginBottom: '1rem' }}>
                  <label className="form-checkbox">
                    <input
                      type="checkbox"
                      checked={sendEmail}
                      onChange={(e) => setSendEmail(e.target.checked)}
                    />
                    <span>Send code to patient email (SMTP required)</span>
                  </label>
                </div>
                <button onClick={handleGenerateClinicCode} className="btn-primary" disabled={loading} style={{ marginBottom: '1rem' }}>
                  Generate code
                </button>
                {generatedCode && (
                  <div style={{ marginTop: '1rem', padding: '1rem', background: 'var(--healthcare-bg)', borderRadius: '8px' }}>
                    <div style={{ marginBottom: '0.75rem' }}>
                      <label className="form-label">Generated code</label>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <input
                          type="text"
                          className="form-input"
                          value={generatedCode.code || ''}
                          readOnly
                          style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: '1.125rem' }}
                        />
                        <button onClick={handleCopyGeneratedCode} className="btn-secondary btn-sm">
                          Copy
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                      <p style={{ margin: '0.25rem 0' }}>Expiry: <span style={{ fontWeight: 600 }}>{generatedCode.expiresAt ? new Date(generatedCode.expiresAt).toLocaleString() : '—'}</span></p>
                      <p style={{ margin: '0.25rem 0' }}>Delivery: <span style={{ fontWeight: 600 }}>{generatedCode.delivery || '—'}</span> {generatedCode.sentTo && `Sent to: ${generatedCode.sentTo}`}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* SMTP Test Section */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>SMTP test:</h3>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1rem' }}>
                  <div className="form-group" style={{ flex: 1 }}>
                    <label className="form-label">Connectivity/auth check</label>
                    <input
                      type="text"
                      className="form-input"
                      value={smtpStatus || '—'}
                      readOnly
                      style={{ fontFamily: 'monospace' }}
                    />
                  </div>
                  <button onClick={handleVerifySmtp} className="btn-secondary" disabled={loading}>
                    Verify SMTP
                  </button>
                </div>
                <div className="form-group" style={{ marginBottom: '1rem' }}>
                  <label className="form-label">Send test email to</label>
                  <input
                    type="email"
                    className="form-input"
                    value={testEmailTo}
                    onChange={(e) => setTestEmailTo(e.target.value)}
                    placeholder="you@example.com"
                  />
                </div>
                <button onClick={handleSendTestEmail} className="btn-primary" disabled={loading}>
                  Send test
                </button>
                <p style={{ marginTop: '0.75rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                  Uses POST /admin/mail/test. If it fails, error details will show in the toast.
                </p>
              </div>

              {/* System Audit Section */}
              <div>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>System audit:</h3>
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button onClick={handleLoadSystemAudit} className="btn-primary" disabled={loading}>
                    Load latest 200
                  </button>
                  <button onClick={handleShowSystemAuditJson} className="btn-secondary">
                    Show JSON
                  </button>
                  <button onClick={handleCopySystemAuditJson} className="btn-secondary">
                    Copy JSON
                  </button>
                </div>
                {systemAuditLogs.length > 0 && (
                  <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                    Loaded {systemAuditLogs.length} system audit entries
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

