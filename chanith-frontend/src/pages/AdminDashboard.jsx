import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import AlertsList from '../components/AlertsList'
import '../styles/PatientDashboard.css'

export default function AdminDashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [user, setUser] = useState(null)
  const [activeSection, setActiveSection] = useState('dashboard')

  // User Activity (Audit Logs)
  const [userActivity, setUserActivity] = useState({
    user: '',
    actionFilter: ''
  })
  const [auditLogs, setAuditLogs] = useState([])
  const [auditLogsJson, setAuditLogsJson] = useState(null)
  const [showUserAuditJson, setShowUserAuditJson] = useState(false)

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
  const [showSystemAuditJson, setShowSystemAuditJson] = useState(false)

  // Analytics / Fraud management
  const [analytics, setAnalytics] = useState(null)
  const [analyticsLoading, setAnalyticsLoading] = useState(false)
  const [analyticsWindowHours, setAnalyticsWindowHours] = useState(24)
  const [analyticsBucketMinutes, setAnalyticsBucketMinutes] = useState(60)
  const [showAnalyticsJson, setShowAnalyticsJson] = useState(false)

  // Biometric support (clear credential_exists)
  const [biometricCredentialId, setBiometricCredentialId] = useState('')
  const [biometricLookup, setBiometricLookup] = useState(null)
  const [biometricSupportLoading, setBiometricSupportLoading] = useState(false)

  // Account requests (no-trust activation + delete approval)
  const [accountRequests, setAccountRequests] = useState([])
  const [accountReqLoading, setAccountReqLoading] = useState(false)

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    loadUserData()
    loadSmtpStatus()
    handleLoadPendingPatients()
    loadAccountRequests()
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
    if (!auditLogsJson) return toast('Please load logs first', 'warning')
    setShowUserAuditJson((v) => !v)
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
      if ((data.patients || []).length > 0 && !selectedPatientId) {
        const first = data.patients[0].patientId
        setSelectedPatientId(first)
        setClinicCodeData((v) => ({ ...v, patientId: first }))
      }
      toast(`Loaded ${data.count || 0} pending patients`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to load pending patients', 'error')
      setPendingPatients([])
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateClinicCode = async () => {
    if (!clinicCodeData.patientId || !String(clinicCodeData.patientId).trim()) {
      toast('Select a patientId before generating a clinic code', 'error')
      return
    }
    if (sendEmail && !String(clinicCodeData.patientId).trim()) {
      toast('patientId is required to email the code', 'error')
      return
    }
    try {
      setLoading(true)
      const data = await api('/clinic/codes', {
        method: 'POST',
        body: {
          patientId: String(clinicCodeData.patientId).trim(),
          expiresMinutes: Number(clinicCodeData.expiresMinutes) || 10,
          sendEmail: sendEmail
        }
      })
      setGeneratedCode(data)
      if (data.warning) toast(data.warning, 'warning')
      toast('Clinic code generated successfully!', 'success')
    } catch (err) {
      toast(err.message || 'Failed to generate clinic code', 'error')
      setGeneratedCode(null)
    } finally {
      setLoading(false)
    }
  }

  const loadAccountRequests = async () => {
    try {
      setAccountReqLoading(true)
      const data = await api('/admin/account-requests?status=PENDING&limit=100')
      setAccountRequests(data.requests || [])
    } catch (err) {
      toast(err.message || 'Failed to load account requests', 'error')
      setAccountRequests([])
    } finally {
      setAccountReqLoading(false)
    }
  }

  const approveAccountRequest = async (id) => {
    try {
      setAccountReqLoading(true)
      await api(`/admin/account-requests/${encodeURIComponent(id)}/approve`, { method: 'POST' })
      toast('Approved', 'success')
      await loadAccountRequests()
    } catch (err) {
      toast(err.message || 'Approve failed', 'error')
    } finally {
      setAccountReqLoading(false)
    }
  }

  const rejectAccountRequest = async (id) => {
    const ok = window.confirm('Reject this request?')
    if (!ok) return
    try {
      setAccountReqLoading(true)
      await api(`/admin/account-requests/${encodeURIComponent(id)}/reject`, { method: 'POST' })
      toast('Rejected', 'warning')
      await loadAccountRequests()
    } catch (err) {
      toast(err.message || 'Reject failed', 'error')
    } finally {
      setAccountReqLoading(false)
    }
  }

  const renderAuditTable = (entries) => {
    if (!entries || entries.length === 0) {
      return <p className="empty-state" style={{ marginTop: '1rem' }}>No entries yet.</p>
    }
    return (
      <div style={{ marginTop: '1rem', overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Time</th>
              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Action</th>
              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Actor</th>
              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {entries.slice(0, 200).map((e, idx) => (
              <tr key={idx} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                <td style={{ padding: '0.75rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                  {e.ts ? new Date(e.ts).toLocaleString() : '—'}
                </td>
                <td style={{ padding: '0.75rem', fontSize: '0.875rem' }}>
                  <span className="status-badge">{e.action || '—'}</span>
                </td>
                <td style={{ padding: '0.75rem', fontSize: '0.875rem' }}>
                  {(e.actor?.username || e.actor?.identifier || e.actor?.userId || '—')}{' '}
                  {e.actor?.role ? `(${e.actor.role})` : ''}
                </td>
                <td style={{ padding: '0.75rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                  {e.details ? JSON.stringify(e.details).slice(0, 220) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }

  const renderSparkBars = (values, { height = 64, color = 'var(--healthcare-primary)' } = {}) => {
    const arr = Array.isArray(values) ? values : []
    if (arr.length === 0) return <div className="empty-state">—</div>
    const max = Math.max(...arr.map((n) => Number(n) || 0), 1)
    return (
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height }}>
        {arr.map((v, idx) => {
          const n = Number(v) || 0
          const pct = Math.max(0, Math.min(100, (n / max) * 100))
          return (
            <div
              key={idx}
              title={`${n}`}
              style={{
                flex: 1,
                height: `${pct}%`,
                background: color,
                opacity: n === 0 ? 0.2 : 0.85,
                borderRadius: '2px',
                minWidth: '2px',
              }}
            />
          )
        })}
      </div>
    )
  }

  const handleLoadAnalytics = async () => {
    try {
      setAnalyticsLoading(true)
      const params = new URLSearchParams()
      params.set('windowHours', String(Number(analyticsWindowHours) || 24))
      params.set('bucketMinutes', String(Number(analyticsBucketMinutes) || 60))
      const data = await api(`/analytics/summary?${params.toString()}`)
      setAnalytics(data)
      toast('Analytics loaded', 'success')
    } catch (err) {
      toast(err.message || 'Failed to load analytics', 'error')
      setAnalytics(null)
    } finally {
      setAnalyticsLoading(false)
    }
  }

  const handleBiometricLookup = async () => {
    const cid = String(biometricCredentialId || '').trim()
    if (!cid) return toast('Enter credentialIdB64u first', 'error')
    try {
      setBiometricSupportLoading(true)
      const out = await api(`/admin/biometrics/lookup?credentialIdB64u=${encodeURIComponent(cid)}`)
      setBiometricLookup(out)
      toast(out.found ? 'Biometric found' : 'No biometric found', out.found ? 'warning' : 'success')
    } catch (err) {
      setBiometricLookup(null)
      toast(err.message || 'Lookup failed', 'error')
    } finally {
      setBiometricSupportLoading(false)
    }
  }

  const handleBiometricDelete = async () => {
    const cid = String(biometricCredentialId || '').trim()
    if (!cid) return toast('Enter credentialIdB64u first', 'error')
    const ok = window.confirm('Delete this biometric credential from the database? The user will need to enroll again.')
    if (!ok) return
    try {
      setBiometricSupportLoading(true)
      const out = await api('/admin/biometrics/delete', { method: 'POST', body: { credentialIdB64u: cid } })
      toast(out.deleted ? 'Biometric deleted' : 'Nothing to delete', out.deleted ? 'success' : 'warning')
      await handleBiometricLookup()
    } catch (err) {
      toast(err.message || 'Delete failed', 'error')
    } finally {
      setBiometricSupportLoading(false)
    }
  }

  const investigateAlert = async (alert) => {
    const actor = alert?.actor || {}
    const userId = actor.userId
    const username = actor.username
    const identifier = actor.identifier
    const role = actor.role
    const actionLike = typeof alert?.type === 'string' && /^(auth|anomaly|patient|dispense|vitals|clinic|biometric)\./.test(alert.type) ? alert.type : ''

    const params = new URLSearchParams()
    if (userId) params.set('userId', userId)
    else if (username) params.set('username', username)
    else if (identifier) params.set('username', identifier)
    if (actionLike) params.set('action', actionLike)

    if (!params.toString()) return toast('No actor/action to investigate for this alert', 'warning')

    try {
      setActiveSection('dashboard')
      setShowUserAuditJson(false)
      setUserActivity({
        user: username ? `${username}${role ? ` (${role})` : ''}` : (identifier || userId || ''),
        actionFilter: actionLike || '',
      })
      setLoading(true)
      const data = await api(`/audit/logs?${params.toString()}`)
      setAuditLogs(data.entries || [])
      setAuditLogsJson(data)
      toast(`Loaded ${data.count || 0} audit entries`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to load audit logs', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleUnlockPasswordReset = async (userId) => {
    if (!userId) return
    if (!confirm(`Unlock password reset for ${userId}?`)) return
    try {
      await api('/admin/password-reset/unlock', { method: 'POST', body: { userId } })
      toast('Password reset unlocked', 'success')
      await handleLoadAnalytics()
    } catch (err) {
      toast(err.message || 'Failed to unlock', 'error')
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
    if (!systemAuditJson) return toast('Please load audit logs first', 'warning')
    setShowSystemAuditJson((v) => !v)
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
          <button
            className={`nav-item ${activeSection === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveSection('dashboard')}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M3 9L12 2L21 9V20C21 20.5304 20.7893 21.0391 20.4142 21.4142C20.0391 21.7893 19.5304 22 19 22H5C4.46957 22 3.96086 21.7893 3.58579 21.4142C3.21071 21.0391 3 20.5304 3 20V9Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M9 22V12H15V22" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Dashboard</span>
          </button>

          <button
            className={`nav-item ${activeSection === 'analytics' ? 'active' : ''}`}
            onClick={() => setActiveSection('analytics')}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M4 19V5" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M4 19H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M8 15V11" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M12 15V7" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M16 15V9" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>Analytics</span>
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
          {activeSection === 'dashboard' && (
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
                    {showUserAuditJson ? 'Hide JSON' : 'Show JSON'}
                  </button>
                  <button onClick={handleCopyUserActivityJson} className="btn-secondary">
                    Copy JSON
                  </button>
                </div>
                {showUserAuditJson && auditLogsJson && (
                  <pre
                    style={{
                      marginTop: '1rem',
                      padding: '1rem',
                      background: 'var(--healthcare-bg)',
                      borderRadius: '8px',
                      overflowX: 'auto',
                      fontSize: '0.8125rem',
                    }}
                  >
                    {JSON.stringify(auditLogsJson, null, 2)}
                  </pre>
                )}
                {auditLogs.length > 0 && (
                  <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                    Loaded {auditLogs.length} log entries
                  </div>
                )}
                {renderAuditTable(auditLogs)}
              </div>

              {/* Account approvals (No-Trust) */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
                  <h3 style={{ marginBottom: 0, fontSize: '1.125rem', fontWeight: 600 }}>Account approvals (No‑Trust)</h3>
                  <button onClick={loadAccountRequests} className="btn-secondary" disabled={accountReqLoading}>
                    Refresh
                  </button>
                </div>
                <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                  New patient/doctor accounts stay pending until approved. Delete requests also require approval.
                </p>

                {accountReqLoading ? (
                  <p className="empty-state">Loading…</p>
                ) : accountRequests.length === 0 ? (
                  <p className="empty-state">No pending requests.</p>
                ) : (
                  <div style={{ marginTop: '1rem', overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                          <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Type</th>
                          <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>User</th>
                          <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Role</th>
                          <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Requested</th>
                          <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {accountRequests.map((r) => {
                          const u = r.user || {}
                          const displayName = u.username || r.username || r.userId
                          const email = u.email || r.email
                          const requestedAt = r.createdAtIso ? new Date(r.createdAtIso).toLocaleString() : '—'
                          const typeLabel = r.type === 'DELETE' ? 'Delete request' : 'Activate request'

                          return (
                            <tr key={r.id} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                              <td style={{ padding: '0.75rem' }}>
                                <span className="status-badge">{typeLabel}</span>
                              </td>
                              <td style={{ padding: '0.75rem' }}>
                                <div style={{ fontWeight: 700 }}>{displayName}</div>
                                <div style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>
                                  {r.userId}
                                </div>
                                {email ? (
                                  <div style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>{email}</div>
                                ) : null}
                              </td>
                              <td style={{ padding: '0.75rem' }}>{u.role || r.role || '—'}</td>
                              <td style={{ padding: '0.75rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                                {requestedAt}
                              </td>
                              <td style={{ padding: '0.75rem' }}>
                                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                                  <button className="btn-primary btn-sm" onClick={() => approveAccountRequest(r.id)} disabled={accountReqLoading}>
                                    Approve
                                  </button>
                                  <button className="btn-secondary btn-sm" onClick={() => rejectAccountRequest(r.id)} disabled={accountReqLoading}>
                                    Reject
                                  </button>
                                  <button
                                    className="btn-secondary btn-sm"
                                    type="button"
                                    onClick={async () => {
                                      try {
                                        await navigator.clipboard.writeText(String(r.userId || ''))
                                        toast('User ID copied', 'success')
                                      } catch {
                                        toast('Copy failed', 'error')
                                      }
                                    }}
                                  >
                                    Copy userId
                                  </button>
                                </div>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
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
                    {generatedCode.warning && (
                      <div className="auth-alert auth-alert-warning" style={{ marginBottom: '1rem' }}>
                        <div className="alert-content">
                          <strong>Delivery warning</strong>
                          <p>{generatedCode.warning}</p>
                        </div>
                      </div>
                    )}
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

              {/* Biometric Support Section */}
              <div style={{ marginBottom: '2rem', paddingBottom: '2rem', borderBottom: '1px solid var(--healthcare-border)' }}>
                <h3 style={{ marginBottom: '0.5rem', fontSize: '1.125rem', fontWeight: 600 }}>Biometric support:</h3>
                <p style={{ marginTop: 0, marginBottom: '1rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                  Use this when a pharmacist sees <span style={{ fontFamily: 'monospace' }}>credential_exists</span>. Paste the shown <span style={{ fontFamily: 'monospace' }}>credentialIdB64u</span>, lookup the owner, and delete stale credentials if needed.
                </p>

                <div className="form-grid" style={{ gridTemplateColumns: '1fr', gap: '1rem', marginBottom: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">credentialIdB64u</label>
                    <input
                      type="text"
                      className="form-input"
                      value={biometricCredentialId}
                      onChange={(e) => setBiometricCredentialId(e.target.value)}
                      placeholder="Paste credentialIdB64u from the pharmacist error…"
                      style={{ fontFamily: 'monospace' }}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button onClick={handleBiometricLookup} className="btn-secondary" disabled={biometricSupportLoading}>
                    Lookup
                  </button>
                  <button onClick={handleBiometricDelete} className="btn-danger" disabled={biometricSupportLoading}>
                    Delete
                  </button>
                  <button
                    onClick={async () => {
                      if (!biometricLookup) return toast('Nothing to copy', 'warning')
                      await navigator.clipboard.writeText(JSON.stringify(biometricLookup, null, 2))
                      toast('Copied', 'success')
                    }}
                    className="btn-secondary"
                    type="button"
                    disabled={!biometricLookup}
                  >
                    Copy JSON
                  </button>
                </div>

                {biometricLookup && (
                  <pre
                    style={{
                      marginTop: '1rem',
                      padding: '1rem',
                      background: 'var(--healthcare-bg)',
                      borderRadius: '8px',
                      overflowX: 'auto',
                      fontSize: '0.8125rem',
                    }}
                  >
                    {JSON.stringify(biometricLookup, null, 2)}
                  </pre>
                )}
              </div>

              {/* System Audit Section */}
              <div>
                <h3 style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>System audit:</h3>
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button onClick={handleLoadSystemAudit} className="btn-primary" disabled={loading}>
                    Load latest 200
                  </button>
                  <button onClick={handleShowSystemAuditJson} className="btn-secondary">
                    {showSystemAuditJson ? 'Hide JSON' : 'Show JSON'}
                  </button>
                  <button onClick={handleCopySystemAuditJson} className="btn-secondary">
                    Copy JSON
                  </button>
                </div>
                {showSystemAuditJson && systemAuditJson && (
                  <pre
                    style={{
                      marginTop: '1rem',
                      padding: '1rem',
                      background: 'var(--healthcare-bg)',
                      borderRadius: '8px',
                      overflowX: 'auto',
                      fontSize: '0.8125rem',
                    }}
                  >
                    {JSON.stringify(systemAuditJson, null, 2)}
                  </pre>
                )}
                {systemAuditLogs.length > 0 && (
                  <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                    Loaded {systemAuditLogs.length} system audit entries
                  </div>
                )}
                {renderAuditTable(systemAuditLogs)}
              </div>
            </div>
          </div>
          )}

          {activeSection === 'analytics' && (
            <div className="dashboard-section">
              <div className="section-header">
                <div>
                  <h1>Analytics</h1>
                  <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.9375rem' }}>
                    Fraud management signals derived from audit logs (rule-based scoring MVP).
                  </p>
                </div>
              </div>

              <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
                <h2 style={{ marginBottom: '1rem', fontSize: '1.25rem', fontWeight: 600 }}>Analytics & Fraud Management</h2>

                <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Window (hours)</label>
                    <input
                      type="number"
                      className="form-input"
                      min="1"
                      max="720"
                      value={analyticsWindowHours}
                      onChange={(e) => setAnalyticsWindowHours(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Bucket (minutes)</label>
                    <select
                      className="form-input"
                      value={analyticsBucketMinutes}
                      onChange={(e) => setAnalyticsBucketMinutes(Number(e.target.value))}
                    >
                      <option value={15}>15</option>
                      <option value={30}>30</option>
                      <option value={60}>60</option>
                    </select>
                  </div>
                  <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end' }}>
                    <button onClick={handleLoadAnalytics} className="btn-primary" disabled={analyticsLoading}>
                      {analyticsLoading ? 'Loading…' : 'Load analytics'}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button
                    onClick={() => setShowAnalyticsJson((v) => !v)}
                    className="btn-secondary"
                    disabled={!analytics}
                  >
                    {showAnalyticsJson ? 'Hide JSON' : 'Show JSON'}
                  </button>
                  <button
                    onClick={async () => {
                      if (!analytics) return toast('Load analytics first', 'warning')
                      await navigator.clipboard.writeText(JSON.stringify(analytics, null, 2))
                      toast('Analytics JSON copied', 'success')
                    }}
                    className="btn-secondary"
                    disabled={!analytics}
                  >
                    Copy JSON
                  </button>
                </div>

                {showAnalyticsJson && analytics && (
                  <pre
                    style={{
                      marginTop: '1rem',
                      padding: '1rem',
                      background: 'var(--healthcare-bg)',
                      borderRadius: '8px',
                      overflowX: 'auto',
                      fontSize: '0.8125rem',
                    }}
                  >
                    {JSON.stringify(analytics, null, 2)}
                  </pre>
                )}
              </div>

              {analytics && (
                <>
	                  <div className="section-grid" style={{ marginBottom: '2rem' }}>
	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Totals</h3>
	                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.95rem' }}>
	                        <div><strong>Events</strong>: {analytics.totals?.events ?? 0}</div>
	                        <div><strong>Anomalies</strong>: {analytics.totals?.anomalies ?? 0}</div>
	                        <div><strong>Login failed</strong>: {analytics.totals?.loginFailed ?? 0}</div>
	                        <div><strong>Login success</strong>: {analytics.totals?.loginSuccess ?? 0}</div>
	                        <div><strong>Login blocked</strong>: {analytics.totals?.loginBlocked ?? 0}</div>
	                        <div><strong>OTP issued</strong>: {analytics.totals?.otpIssued ?? 0}</div>
	                        <div><strong>OTP verified</strong>: {analytics.totals?.otpVerified ?? 0}</div>
	                        <div><strong>OTP failures</strong>: {analytics.totals?.otpVerifyFailed ?? 0}</div>
	                        <div><strong>Reset requested</strong>: {analytics.totals?.passwordResetRequested ?? 0}</div>
	                        <div><strong>Reset completed</strong>: {analytics.totals?.passwordResetCompleted ?? 0}</div>
	                        <div><strong>Reset locked</strong>: {analytics.totals?.passwordResetLocked ?? 0}</div>
	                        <div><strong>Step-up issued</strong>: {analytics.totals?.newDeviceStepUpIssued ?? 0}</div>
	                        <div><strong>Step-up verified</strong>: {analytics.totals?.newDeviceStepUpVerified ?? 0}</div>
	                        <div><strong>Device bind failed</strong>: {analytics.totals?.deviceBindFailed ?? 0}</div>
	                        <div><strong>Vitals rejected</strong>: {analytics.totals?.vitalsUploadRejected ?? 0}</div>
	                        <div><strong>Break-glass reads</strong>: {analytics.totals?.vitalsReadBreakGlass ?? 0}</div>
	                        <div><strong>Dispense blocked</strong>: {analytics.totals?.dispenseBlocked ?? 0}</div>
	                      </div>
	                      <p style={{ marginTop: '0.75rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Window: last {analytics.windowHours}h • Buckets: {analytics.bucketMinutes}m
	                      </p>
	                    </div>

                    <div className="healthcare-card">
                      <h3 style={{ marginBottom: '0.5rem' }}>Event trend</h3>
                      {renderSparkBars((analytics.series || []).map((b) => b.total))}
                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                        Bars: total events per bucket
                      </p>
                    </div>

	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Login failures</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.loginFailed), { color: 'var(--healthcare-danger, #e55353)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: auth.login_failed per bucket
	                      </p>
	                    </div>
	                  </div>

	                  <div className="section-grid" style={{ marginBottom: '2rem' }}>
	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Anomalies</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.anomalies), { color: 'var(--healthcare-warning, #f5a623)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: anomaly.* per bucket
	                      </p>
	                    </div>

	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>OTP failures</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.otpVerifyFailed), { color: 'var(--healthcare-warning, #f5a623)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: auth.otp_verify_failed per bucket
	                      </p>
	                    </div>

	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Password reset lockouts</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.passwordResetLocked), { color: 'var(--healthcare-danger, #e55353)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: auth.password_reset_locked per bucket
	                      </p>
	                    </div>

	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Dispense blocked</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.dispenseBlocked), { color: 'var(--healthcare-danger, #e55353)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: dispense.blocked per bucket
	                      </p>
	                    </div>

	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Device bind failures</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.deviceBindFailed), { color: 'var(--healthcare-warning, #f5a623)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: patient.device_bind_failed per bucket
	                      </p>
	                    </div>

	                    <div className="healthcare-card">
	                      <h3 style={{ marginBottom: '0.5rem' }}>Break-glass vitals reads</h3>
	                      {renderSparkBars((analytics.series || []).map((b) => b.vitalsReadBreakGlass), { color: 'var(--healthcare-danger, #e55353)' })}
	                      <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Bars: vitals.read_break_glass per bucket
	                      </p>
	                    </div>
	                  </div>

	                  <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
	                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: '1rem', flexWrap: 'wrap' }}>
	                      <div>
	                        <h3 style={{ marginBottom: '0.25rem' }}>Suspicious activity</h3>
	                        <p style={{ margin: 0, color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                          Alerts are derived from anomalies + high-risk patterns (bruteforce, OTP abuse, repeated blocked dispense, break-glass).
	                        </p>
	                      </div>
	                      <div style={{ color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
	                        Total: <strong>{analytics.alertTotals?.total ?? (analytics.alerts || []).length}</strong>{' '}
	                        {analytics.alertTotals?.bySeverity?.critical ? <>• Critical: <strong>{analytics.alertTotals.bySeverity.critical}</strong>{' '}</> : null}
	                        {analytics.alertTotals?.bySeverity?.high ? <>• High: <strong>{analytics.alertTotals.bySeverity.high}</strong>{' '}</> : null}
	                        {analytics.alertTotals?.bySeverity?.medium ? <>• Medium: <strong>{analytics.alertTotals.bySeverity.medium}</strong>{' '}</> : null}
	                        {analytics.alertTotals?.bySeverity?.low ? <>• Low: <strong>{analytics.alertTotals.bySeverity.low}</strong>{' '}</> : null}
	                      </div>
	                    </div>

	                    {(analytics.alerts || []).length === 0 ? (
	                      <p className="empty-state" style={{ marginTop: '1rem' }}>No alerts in this window</p>
	                    ) : (
	                      <AlertsList alerts={analytics.alerts || []} limit={25} onInvestigate={investigateAlert} />
	                    )}
	                  </div>

	                  <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
	                    <h3 style={{ marginBottom: '1rem' }}>Top actions</h3>
	                    {(analytics.topActions || []).length === 0 ? (
	                      <p className="empty-state">No data</p>
                    ) : (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Action</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Count</th>
                            </tr>
                          </thead>
                          <tbody>
                            {analytics.topActions.slice(0, 15).map((a) => (
                              <tr key={a.action} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                                <td style={{ padding: '0.75rem', fontFamily: 'monospace' }}>{a.action}</td>
                                <td style={{ padding: '0.75rem' }}>{a.count}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Risky users (score)</h3>
                    {(analytics.riskyUsers || []).length === 0 ? (
                      <p className="empty-state">No risky users found</p>
                    ) : (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>User</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Role</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Score</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Reasons</th>
                            </tr>
                          </thead>
                          <tbody>
                            {analytics.riskyUsers.slice(0, 10).map((r) => (
                              <tr key={r.userId} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                                <td style={{ padding: '0.75rem' }}>
                                  <div style={{ fontWeight: 600 }}>{r.username || r.userId}</div>
                                  <div style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>{r.userId}</div>
                                </td>
                                <td style={{ padding: '0.75rem' }}>{r.role || '—'}</td>
                                <td style={{ padding: '0.75rem' }}>{r.score}</td>
                                <td style={{ padding: '0.75rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                                  {(r.reasons || []).slice(0, 3).join(' • ') || '—'}
                                  {r.passwordResetLockedAt && (
                                    <div style={{ marginTop: '0.25rem' }}>
                                      <span className="status-badge">RESET LOCKED</span>{' '}
                                      <span style={{ fontFamily: 'monospace' }}>{new Date(r.passwordResetLockedAt).toLocaleString()}</span>
                                    </div>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Suspicious identifiers</h3>
                    {(analytics.riskyIdentifiers || []).length === 0 ? (
                      <p className="empty-state">No identifiers flagged</p>
                    ) : (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Identifier</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Score</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Counts</th>
                            </tr>
                          </thead>
                          <tbody>
                            {analytics.riskyIdentifiers.slice(0, 10).map((r) => (
                              <tr key={r.identifier} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                                <td style={{ padding: '0.75rem', fontFamily: 'monospace' }}>{r.identifier}</td>
                                <td style={{ padding: '0.75rem' }}>{r.score}</td>
                                <td style={{ padding: '0.75rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                                  {Object.entries(r.counts || {}).map(([k, v]) => `${k}:${v}`).slice(0, 3).join(' • ') || '—'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  <div className="healthcare-card">
                    <h3 style={{ marginBottom: '1rem' }}>Password reset lockouts</h3>
                    {(analytics.lockedUsers || []).length === 0 ? (
                      <p className="empty-state">No lockouts</p>
                    ) : (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>User</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Role</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Locked at</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Reason</th>
                              <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {analytics.lockedUsers.slice(0, 15).map((u) => (
                              <tr key={u.userId} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                                <td style={{ padding: '0.75rem' }}>
                                  <div style={{ fontWeight: 600 }}>{u.username || u.userId}</div>
                                  <div style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>{u.userId}</div>
                                </td>
                                <td style={{ padding: '0.75rem' }}>{u.role}</td>
                                <td style={{ padding: '0.75rem', fontFamily: 'monospace' }}>{u.lockedAt ? new Date(u.lockedAt).toLocaleString() : '—'}</td>
                                <td style={{ padding: '0.75rem', color: 'var(--healthcare-text-muted)' }}>{u.reason || '—'}</td>
                                <td style={{ padding: '0.75rem' }}>
                                  <button className="btn-secondary" onClick={() => handleUnlockPasswordReset(u.userId)}>
                                    Unlock
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
