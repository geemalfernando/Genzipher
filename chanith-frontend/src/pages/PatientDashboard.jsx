import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import '../styles/PatientDashboard.css'

export default function PatientDashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [activeSection, setActiveSection] = useState('wallet')
  const [loading, setLoading] = useState(true)
  
  // Profile data
  const [profile, setProfile] = useState(null)
  const [user, setUser] = useState(null)
  
  // Appointments
  const [appointments, setAppointments] = useState([])
  const [doctors, setDoctors] = useState([])
  const [appointmentForm, setAppointmentForm] = useState({
    doctorId: '',
    appointmentDate: '',
    appointmentTime: '',
    notes: ''
  })
  
  // MFA
  const [mfaEmail, setMfaEmail] = useState('')
  const [disableOtp, setDisableOtp] = useState('')
  const [disableOtpRequestId, setDisableOtpRequestId] = useState(null)
  
  // Device
  const [deviceId, setDeviceId] = useState(null)
  const [trustedDevices, setTrustedDevices] = useState([])
  const [loginDevices, setLoginDevices] = useState([])
  const [loginDevicesUserMeta, setLoginDevicesUserMeta] = useState(null)
  const [removeTrustedState, setRemoveTrustedState] = useState({ step: 'idle', otpRequestId: null, deviceId: '', otp: '' })

  // Prescription wallet
  const [wallet, setWallet] = useState([])
  const [walletJson, setWalletJson] = useState(null)
  const [showWalletJson, setShowWalletJson] = useState(false)
  
  // DID & Data Key
  const [did, setDid] = useState(null)
  const [patientToken, setPatientToken] = useState(null)

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    loadInitialData()
  }, [token, navigate])

  const loadInitialData = async () => {
    if (!token) return
    try {
      setLoading(true)
      // Load data sequentially to avoid overwhelming the API
      await loadProfile()
      await loadDoctors()
      await loadAppointments()
      await loadWallet()
      await loadTrustedDevices()
      await loadLoginDevices()
    } catch (err) {
      console.error('Load initial data error:', err)
      // Silently fail - don't break the UI
    } finally {
      setLoading(false)
    }
  }

  const loadProfile = async () => {
    try {
      const data = await api('/patients/me/profile')
      setProfile(data.profile)
      setUser(data.user)
      setPatientToken(data.patientToken)
      setMfaEmail(data.user?.email || '')
      setDid(data.profile?.did || null)
    } catch (err) {
      console.error('Profile load error:', err)
    }
  }

  const loadDoctors = async () => {
    try {
      // Load all users and filter for doctors
      const data = await api('/demo/users')
      const doctorUsers = data.users?.filter(u => u.role === 'doctor') || []
      setDoctors(doctorUsers)
    } catch (err) {
      console.error('Doctors load error:', err)
      setDoctors([])
    }
  }

  const loadAppointments = async () => {
    try {
      const data = await api('/appointments')
      setAppointments(data.appointments || [])
    } catch (err) {
      console.error('Appointments load error:', err)
    }
  }

  const loadWallet = async () => {
    try {
      const data = await api('/patients/wallet')
      setWallet(data.items || [])
      setWalletJson(data)
    } catch (err) {
      console.error('Wallet load error:', err)
      setWallet([])
      setWalletJson(null)
    }
  }

  const loadTrustedDevices = async () => {
    try {
      const data = await api('/auth/trusted-devices')
      setTrustedDevices(data.devices || [])
    } catch (err) {
      console.error('Trusted devices load error:', err)
      setTrustedDevices([])
    }
  }

  const loadLoginDevices = async () => {
    try {
      const data = await api('/auth/login-devices')
      setLoginDevices(data.devices || [])
      setLoginDevicesUserMeta(data.user || null)
    } catch (err) {
      console.error('Login devices load error:', err)
      setLoginDevices([])
      setLoginDevicesUserMeta(null)
    }
  }

  const requestRemoveTrustedDevice = async (deviceId) => {
    try {
      const out = await api('/auth/trusted-devices/remove/request', {
        method: 'POST',
        body: { deviceId },
      })
      setRemoveTrustedState({ step: 'otp', otpRequestId: out.otpRequestId, deviceId, otp: '' })
      toast(out.delivery === 'email' ? 'OTP sent to your email. Enter it to confirm removal.' : 'OTP issued (MVP). Check server logs.', 'warning')
    } catch (err) {
      toast(err.message || 'Failed to start removal', 'error')
    }
  }

  const confirmRemoveTrustedDevice = async () => {
    try {
      const { otpRequestId, otp } = removeTrustedState
      if (!otpRequestId) return toast('No pending removal request', 'error')
      if (!otp || otp.trim().length !== 6) return toast('Enter the 6-digit OTP', 'error')
      await api('/auth/trusted-devices/remove/confirm', { method: 'POST', body: { otpRequestId, otp } })
      toast('Trusted device removed', 'success')
      setRemoveTrustedState({ step: 'idle', otpRequestId: null, deviceId: '', otp: '' })
      await loadTrustedDevices()
    } catch (err) {
      toast(err.message || 'Failed to remove trusted device', 'error')
    }
  }

  const handleBookAppointment = async (e) => {
    e.preventDefault()
    try {
      await api('/appointments', {
        method: 'POST',
        body: appointmentForm
      })
      toast('Appointment booked successfully!', 'success')
      setAppointmentForm({ doctorId: '', appointmentDate: '', appointmentTime: '', notes: '' })
      loadAppointments()
    } catch (err) {
      toast(err.message || 'Failed to book appointment', 'error')
    }
  }

  const handleEnableMFA = async () => {
    try {
      await api('/patients/enable-mfa', {
        method: 'POST',
        body: { method: 'EMAIL_OTP', email: mfaEmail || undefined }
      })
      toast('MFA enabled successfully!', 'success')
      loadProfile()
    } catch (err) {
      toast(err.message || 'Failed to enable MFA', 'error')
    }
  }

  const handleRequestDisableMFA = async () => {
    try {
      const data = await api('/patients/disable-mfa/request', {
        method: 'POST'
      })
      setDisableOtpRequestId(data.otpRequestId)
      toast('Disable code sent to your email', 'success')
    } catch (err) {
      toast(err.message || 'Failed to request disable code', 'error')
    }
  }

  const handleConfirmDisableMFA = async () => {
    try {
      await api('/patients/disable-mfa/confirm', {
        method: 'POST',
        body: { otpRequestId: disableOtpRequestId, otp: disableOtp }
      })
      toast('MFA disabled successfully', 'success')
      setDisableOtp('')
      setDisableOtpRequestId(null)
      loadProfile()
    } catch (err) {
      toast(err.message || 'Failed to disable MFA', 'error')
    }
  }

  const handleIssueDID = async () => {
    try {
      const data = await api('/patients/issue-did', {
        method: 'POST'
      })
      setDid(data.did)
      toast('DID issued successfully!', 'success')
      loadProfile()
    } catch (err) {
      toast(err.message || 'Failed to issue DID', 'error')
    }
  }

  const handleProvisionDataKey = async () => {
    try {
      const data = await api('/patients/provision-data-key', {
        method: 'POST'
      })
      setPatientToken(data.patientToken)
      toast('Data key provisioned successfully!', 'success')
      loadProfile()
    } catch (err) {
      toast(err.message || 'Failed to provision data key', 'error')
    }
  }

  const handleBindDevice = async () => {
    try {
      // Generate a simple device ID
      const deviceId = `web_${Date.now().toString(36)}${Math.random().toString(36).substr(2, 9)}`
      
      // For demo purposes, we'll use a simple approach
      // In production, you'd generate proper keys
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\nDEMO_KEY\n-----END PUBLIC KEY-----`
      
      await api('/patients/bind-device', {
        method: 'POST',
        body: {
          deviceId,
          publicKeyPem,
          keyAlg: 'ES256'
        }
      })
      setDeviceId(deviceId)
      toast('Device binding initiated. Please verify.', 'success')
    } catch (err) {
      toast(err.message || 'Failed to bind device', 'error')
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
            <p>Patient Portal</p>
          </div>
        </div>

        <nav className="patient-sidebar-nav">
          <button 
            className={`nav-item ${activeSection === 'appointments' ? 'active' : ''}`}
            onClick={() => setActiveSection('appointments')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M8 2V6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M16 2V6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M3 10H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M19 4H5C3.89543 4 3 4.89543 3 6V20C3 21.1046 3.89543 22 5 22H19C20.1046 22 21 21.1046 21 20V6C21 4.89543 20.1046 4 19 4Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Appointments</span>
          </button>
          <button 
            className={`nav-item ${activeSection === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveSection('profile')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M20 21V19C20 17.9391 19.5786 16.9217 18.8284 16.1716C18.0783 15.4214 17.0609 15 16 15H8C6.93913 15 5.92172 15.4214 5.17157 16.1716C4.42143 16.9217 4 17.9391 4 19V21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M12 11C14.2091 11 16 9.20914 16 7C16 4.79086 14.2091 3 12 3C9.79086 3 8 4.79086 8 7C8 9.20914 9.79086 11 12 11Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span>Profile</span>
          </button>
          <button
            className={`nav-item ${activeSection === 'wallet' ? 'active' : ''}`}
            onClick={() => setActiveSection('wallet')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M21 7H3V5C3 3.89543 3.89543 3 5 3H19C20.1046 3 21 3.89543 21 5V7Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M3 7H21V19C21 20.1046 20.1046 21 19 21H5C3.89543 21 3 20.1046 3 19V7Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M17 15H19" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>Wallet</span>
          </button>
          <button 
            className={`nav-item ${activeSection === 'security' ? 'active' : ''}`}
            onClick={() => setActiveSection('security')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M12 8V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M12 16H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>Security</span>
          </button>
          <button 
            className={`nav-item ${activeSection === 'devices' ? 'active' : ''}`}
            onClick={() => setActiveSection('devices')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="5" y="2" width="14" height="20" rx="2" stroke="currentColor" strokeWidth="2"/>
              <path d="M12 18H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>Devices</span>
          </button>
          <button 
            className={`nav-item ${activeSection === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveSection('settings')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 15C13.6569 15 15 13.6569 15 12C15 10.3431 13.6569 9 12 9C10.3431 9 9 10.3431 9 12C9 13.6569 10.3431 15 12 15Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M19.4 15C19.2669 15.3016 19.2272 15.6362 19.286 15.9606C19.3448 16.285 19.4995 16.5843 19.73 16.82L19.79 16.88C19.976 17.0657 20.1235 17.2863 20.2241 17.5291C20.3248 17.7719 20.3766 18.0322 20.3766 18.295C20.3766 18.5578 20.3248 18.8181 20.2241 19.0609C20.1235 19.3037 19.976 19.5243 19.79 19.71C19.6043 19.896 19.3837 20.0435 19.1409 20.1441C18.8981 20.2448 18.6378 20.2966 18.375 20.2966C18.1122 20.2966 17.8519 20.2448 17.6091 20.1441C17.3663 20.0435 17.1457 19.896 16.96 19.71L16.9 19.65C16.6643 19.4195 16.365 19.2648 16.0406 19.206C15.7162 19.1472 15.3816 19.1869 15.08 19.32C14.7842 19.4468 14.532 19.6572 14.3543 19.9255C14.1766 20.1938 14.0813 20.5082 14.08 20.83V21C14.08 21.5304 13.8693 22.0391 13.4942 22.4142C13.1191 22.7893 12.6104 23 12.08 23C11.5496 23 11.0409 22.7893 10.6658 22.4142C10.2907 22.0391 10.08 21.5304 10.08 21V20.91C10.0723 20.579 9.95956 20.258 9.75756 19.992C9.55556 19.726 9.27418 19.5284 8.95 19.43C8.63761 19.3362 8.35708 19.1335 8.15035 18.8514C7.94362 18.5693 7.82085 18.2213 7.8 17.86L7.79 17.79C7.79043 17.3918 7.63228 17.0098 7.34763 16.7252C7.06298 16.4405 6.68101 16.2824 6.29 16.28H6.21C5.819 16.2824 5.43702 16.4405 5.15237 16.7252C4.86772 17.0098 4.70957 17.3918 4.71 17.79C4.72 18.1513 4.59723 18.4993 4.3905 18.7814C4.18377 19.0635 3.90324 19.2662 3.59 19.36C3.26596 19.4584 2.98458 19.656 2.78256 19.922C2.58056 20.188 2.46785 20.509 2.46 20.84V21C2.46 21.5304 2.24929 22.0391 1.87421 22.4142C1.49914 22.7893 0.990407 23 0.46 23C-0.0704066 23 -0.579144 22.7893 -0.954214 22.4142C-1.32929 22.0391 -1.54 21.5304 -1.54 21V20.91C-1.54769 20.5791 -1.66044 20.2581 -1.86244 19.9921C-2.06444 19.7261 -2.34582 19.5285 -2.67 19.43C-2.98239 19.3362 -3.26292 19.1335 -3.46965 18.8514C-3.67638 18.5693 -3.79915 18.2213 -3.82 17.86L-3.83 17.79C-3.82957 17.3918 -3.98772 17.0098 -4.27237 16.7252C-4.55702 16.4405 -4.93899 16.2824 -5.33 16.28H-5.41C-5.801 16.2824 -6.18298 16.4405 -6.46763 16.7252C-6.75228 17.0098 -6.91043 17.3918 -6.91 17.79C-6.9 18.1513 -7.02277 18.4993 -7.2295 18.7814C-7.43623 19.0635 -7.71676 19.2662 -8.03 19.36C-8.35404 19.4584 -8.63542 19.656 -8.83744 19.922C-9.03944 20.188 -9.15215 20.509 -9.16 20.84V21C-9.16 21.5304 -9.37071 22.0391 -9.74579 22.4142C-10.1209 22.7893 -10.6296 23 -11.16 23C-11.6904 23 -12.1991 22.7893 -12.5742 22.4142C-12.9493 22.0391 -13.16 21.5304 -13.16 21V20.91C-13.1677 20.5791 -13.2804 20.2581 -13.4824 19.9921C-13.6844 19.7261 -13.9658 19.5285 -14.29 19.43C-14.6024 19.3362 -14.8829 19.1335 -15.0896 18.8514C-15.2964 18.5693 -15.4191 18.2213 -15.44 17.86L-15.45 17.79C-15.4496 17.3918 -15.6077 17.0098 -15.8924 16.7252C-16.177 16.4405 -16.559 16.2824 -16.95 16.28H-17.03C-17.421 16.2824 -17.803 16.4405 -18.0876 16.7252C-18.3723 17.0098 -18.5304 17.3918 -18.53 17.79C-18.52 18.1513 -18.6428 18.4993 -18.8495 18.7814C-19.0562 19.0635 -19.3368 19.2662 -19.65 19.36C-19.974 19.4584 -20.2554 19.656 -20.4574 19.922C-20.6594 20.188 -20.7722 20.509 -20.78 20.84V21C-20.78 21.5304 -20.9907 22.0391 -21.3658 22.4142C-21.7409 22.7893 -22.2496 23 -22.78 23C-23.3104 23 -23.8191 22.7893 -24.1942 22.4142C-24.5693 22.0391 -24.78 21.5304 -24.78 21V20.91C-24.7877 20.5791 -24.9004 20.2581 -25.1024 19.9921C-25.3044 19.7261 -25.5858 19.5285 -25.91 19.43" stroke="currentColor" strokeWidth="2"/>
            </svg>
            <span>Settings</span>
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
          {activeSection === 'appointments' && (
            <div className="dashboard-section">
              <div className="section-header">
                <h1>Appointments</h1>
                <button onClick={loadAppointments} className="refresh-btn">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M1 4V10H7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M23 20V14H17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  Refresh
                </button>
              </div>

              <div className="section-grid">
                <div className="healthcare-card">
                  <h2>Book Appointment with Doctor</h2>
                  <form onSubmit={handleBookAppointment} className="appointment-form">
                    <div className="form-group">
                      <label>Select Doctor *</label>
                      <select
                        value={appointmentForm.doctorId}
                        onChange={(e) => setAppointmentForm({ ...appointmentForm, doctorId: e.target.value })}
                        required
                        className="form-input"
                      >
                        <option value="">Select a doctor...</option>
                        {doctors.map(doctor => (
                          <option key={doctor.id} value={doctor.id}>{doctor.username}</option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label>Appointment Date *</label>
                      <input
                        type="date"
                        value={appointmentForm.appointmentDate}
                        onChange={(e) => setAppointmentForm({ ...appointmentForm, appointmentDate: e.target.value })}
                        required
                        className="form-input"
                      />
                    </div>
                    <div className="form-group">
                      <label>Appointment Time *</label>
                      <input
                        type="time"
                        value={appointmentForm.appointmentTime}
                        onChange={(e) => setAppointmentForm({ ...appointmentForm, appointmentTime: e.target.value })}
                        required
                        className="form-input"
                      />
                    </div>
                    <div className="form-group">
                      <label>Notes (optional)</label>
                      <textarea
                        value={appointmentForm.notes}
                        onChange={(e) => setAppointmentForm({ ...appointmentForm, notes: e.target.value })}
                        placeholder="Any additional notes..."
                        rows="4"
                        className="form-input"
                      />
                    </div>
                    <button type="submit" className="btn-primary">Book Appointment</button>
                  </form>
                </div>

                <div className="healthcare-card">
                  <h2>My Appointments</h2>
                  <button onClick={loadAppointments} className="btn-primary" style={{ marginBottom: '1.5rem' }}>
                    Load Appointments
                  </button>
                  {appointments.length === 0 ? (
                    <p className="empty-state">Click to load your appointments</p>
                  ) : (
                    <div className="appointments-list">
                      {appointments.map(apt => (
                        <div key={apt.id} className="appointment-item">
                          <div className="appointment-header">
                            <span className="appointment-status">{apt.status}</span>
                            <span className="appointment-date">{apt.appointmentDate} at {apt.appointmentTime}</span>
                          </div>
                          <div className="appointment-details">
                            <p><strong>Doctor ID:</strong> {apt.doctorId}</p>
                            {apt.notes && <p><strong>Notes:</strong> {apt.notes}</p>}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeSection === 'wallet' && (
            <div className="dashboard-section">
              <div className="section-header">
                <div>
                  <h1>Prescription Wallet</h1>
                  <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.9375rem' }}>
                    Active prescriptions with status (Valid/Used/Expired) and a QR payload for pharmacy verification.
                  </p>
                </div>
                <button onClick={loadWallet} className="refresh-btn">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M1 4V10H7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M23 20V14H17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  Refresh
                </button>
              </div>

              <div className="healthcare-card" style={{ marginBottom: '1.25rem' }}>
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button onClick={() => setShowWalletJson((v) => !v)} className="btn-secondary" type="button">
                    {showWalletJson ? 'Hide JSON' : 'View JSON'}
                  </button>
                  <button
                    onClick={async () => {
                      if (!walletJson) return toast('Nothing to copy', 'warning')
                      await navigator.clipboard.writeText(JSON.stringify(walletJson, null, 2))
                      toast('JSON copied', 'success')
                    }}
                    className="btn-secondary"
                    type="button"
                  >
                    Copy JSON
                  </button>
                </div>
                {showWalletJson && (
                  <pre style={{ marginTop: '1rem', whiteSpace: 'pre-wrap', fontSize: '0.85rem' }}>
                    {JSON.stringify(walletJson, null, 2)}
                  </pre>
                )}
              </div>

              {wallet.length === 0 ? (
                <div className="healthcare-card">
                  <p className="empty-state">No prescriptions yet.</p>
                </div>
              ) : (
                <div className="section-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
                  {wallet.map((item) => {
                    const status = item.status || '—'
                    const statusColor =
                      status === 'VALID'
                        ? 'var(--healthcare-success)'
                        : status === 'USED'
                          ? 'var(--healthcare-warning)'
                          : status === 'EXPIRED'
                            ? 'var(--healthcare-danger)'
                            : 'var(--healthcare-border)'
                    return (
                      <div key={item.rxId || item.id} className="healthcare-card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'baseline' }}>
                          <h2 style={{ margin: 0, fontSize: '1.1rem' }}>{item.medicineId || 'Prescription'}</h2>
                          <span className="appointment-status" style={{ borderColor: statusColor, color: statusColor }}>
                            {status}
                          </span>
                        </div>

                        <div style={{ marginTop: '0.75rem', fontSize: '0.95rem' }}>
                          <div><strong>Dosage:</strong> {item.dosage || '—'}</div>
                          <div><strong>Duration:</strong> {item.durationDays ? `${item.durationDays} days` : '—'}</div>
                          <div><strong>Expires:</strong> {item.expiry ? new Date(item.expiry).toLocaleString() : '—'}</div>
                          {item.usedAt && <div><strong>Used:</strong> {new Date(item.usedAt).toLocaleString()}</div>}
                          <div style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                            Verification: {item.checks?.signatureOk ? 'Verified ✓' : 'Unverified ✗'}
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '1rem' }}>
                          <button
                            className="btn-primary"
                            type="button"
                            onClick={async () => {
                              if (!item.qrPayload) return toast('No QR payload', 'warning')
                              await navigator.clipboard.writeText(item.qrPayload)
                              toast('QR payload copied (paste into pharmacy verify)', 'success')
                            }}
                          >
                            Copy QR payload
                          </button>
                          <button
                            className="btn-secondary"
                            type="button"
                            onClick={async () => {
                              await navigator.clipboard.writeText(JSON.stringify(item, null, 2))
                              toast('Copied', 'success')
                            }}
                          >
                            Copy details
                          </button>
                        </div>

                        <details style={{ marginTop: '0.75rem' }}>
                          <summary style={{ cursor: 'pointer', color: 'var(--healthcare-text-muted)' }}>Show QR payload</summary>
                          <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.85rem' }}>{item.qrPayload || '—'}</pre>
                        </details>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {activeSection === 'profile' && (
            <div className="dashboard-section">
              <div className="section-header">
                <h1>Profile</h1>
                <button onClick={loadProfile} className="refresh-btn">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M1 4V10H7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M23 20V14H17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  Refresh
                </button>
              </div>

              <div className="healthcare-card">
                <h2>Profile Information</h2>
                <div className="profile-data">
                  <pre>{JSON.stringify({
                    username: user?.username || '—',
                    email: user?.email || '—',
                    status: profile?.status || '—',
                    trustScore: profile?.trustScore ?? null,
                    trustExplainTop3: profile?.trustExplainTop3 || [],
                    did: profile?.did || null,
                    patientToken: patientToken || null,
                    mfaEnabled: user?.mfaEnabled || false,
                    mfaMethod: user?.mfaMethod || 'NONE',
                    createdFromDeviceId: loginDevicesUserMeta?.createdFromDeviceId || null,
                    lastLoginDeviceId: loginDevicesUserMeta?.lastLoginDeviceId || null,
                    lastLoginAt: loginDevicesUserMeta?.lastLoginAt || null,
                  }, null, 2)}</pre>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'security' && (
            <div className="dashboard-section">
              <div className="section-header">
                <h1>Security Settings</h1>
              </div>

              <div className="section-grid">
                <div className="healthcare-card">
                  <h2>Enable MFA (Email OTP)</h2>
                  <div className="form-group">
                    <label>Email (optional)</label>
                    <input
                      type="email"
                      value={mfaEmail}
                      onChange={(e) => setMfaEmail(e.target.value)}
                      placeholder="your@email.com"
                      className="form-input"
                    />
                  </div>
                  <button onClick={handleEnableMFA} className="btn-primary" disabled={user?.mfaEnabled}>
                    {user?.mfaEnabled ? 'MFA Already Enabled' : 'Enable Email OTP MFA'}
                  </button>
                </div>

                <div className="healthcare-card">
                  <h2>Disable MFA</h2>
                  {!disableOtpRequestId ? (
                    <button onClick={handleRequestDisableMFA} className="btn-danger" disabled={!user?.mfaEnabled}>
                      Send disable code
                    </button>
                  ) : (
                    <div>
                      <div className="form-group">
                        <label>Enter OTP Code</label>
                        <input
                          type="text"
                          value={disableOtp}
                          onChange={(e) => setDisableOtp(e.target.value)}
                          placeholder="123456"
                          className="form-input"
                        />
                      </div>
                      <button onClick={handleConfirmDisableMFA} className="btn-danger">Confirm Disable</button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeSection === 'devices' && (
            <div className="dashboard-section">
              <div className="section-header">
                <h1>Device Management</h1>
              </div>

              <div className="section-grid">
                <div className="healthcare-card">
                  <h2>Trusted Devices</h2>
                  <p style={{ marginBottom: '1rem', color: 'var(--healthcare-text-muted)' }}>
                    Devices trusted for OTP bypass
                  </p>
                  {trustedDevices.length === 0 ? (
                    <p className="empty-state">No trusted devices</p>
                  ) : (
                    <div className="devices-list">
                      {trustedDevices.map((device, idx) => (
                        <div key={idx} className="device-item">
                          <span style={{ fontFamily: 'monospace' }}>{device.deviceId}</span>
                          <span className="device-date">
                            last {new Date(device.lastUsedAt).toLocaleDateString()}, {new Date(device.lastUsedAt).toLocaleTimeString()}
                            {' '}expires {new Date(device.expiresAt).toLocaleDateString()}
                          </span>
                          <button
                            onClick={() => requestRemoveTrustedDevice(device.deviceId)}
                            className="btn-danger"
                            style={{ marginLeft: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
                          >
                            Remove (email OTP)
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  <button onClick={loadTrustedDevices} className="refresh-btn" style={{ marginTop: '1rem' }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M1 4V10H7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M23 20V14H17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    Refresh
                  </button>

                  {removeTrustedState.step === 'otp' && (
                    <div className="healthcare-card" style={{ marginTop: '1rem', background: 'var(--healthcare-bg)' }}>
                      <h3 style={{ marginBottom: '0.5rem' }}>Confirm removal</h3>
                      <p style={{ marginBottom: '0.75rem', color: 'var(--healthcare-text-muted)' }}>
                        Enter the OTP sent to your email to remove: <span style={{ fontFamily: 'monospace' }}>{removeTrustedState.deviceId}</span>
                      </p>
                      <div className="form-group">
                        <label>OTP</label>
                        <input
                          type="text"
                          className="form-input"
                          value={removeTrustedState.otp}
                          onChange={(e) => setRemoveTrustedState((s) => ({ ...s, otp: e.target.value }))}
                          placeholder="123456"
                          inputMode="numeric"
                        />
                      </div>
                      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <button onClick={confirmRemoveTrustedDevice} className="btn-primary">Confirm</button>
                        <button onClick={() => setRemoveTrustedState({ step: 'idle', otpRequestId: null, deviceId: '', otp: '' })} className="btn-secondary">Cancel</button>
                      </div>
                      <p style={{ marginTop: '0.75rem', fontSize: '0.875rem', color: 'var(--healthcare-text-muted)' }}>
                        otpRequestId: <span style={{ fontFamily: 'monospace' }}>{removeTrustedState.otpRequestId}</span>
                      </p>
                    </div>
                  )}
                </div>

                <div className="healthcare-card">
                  <h2>Device Binding</h2>
                  <p style={{ marginBottom: '1rem', color: 'var(--healthcare-text-muted)' }}>
                    Automatic: this browser generates a device key, binds once, then signs challenges automatically (no manual copy/paste).
                  </p>
                  <p style={{ marginBottom: '1rem' }}>
                    <strong>Device ID:</strong> {deviceId || '—'}
                  </p>
                  <button onClick={handleBindDevice} className="btn-primary">Bind/Verify now</button>
                </div>

                <div className="healthcare-card">
                  <h2>Login Devices</h2>
                  <p style={{ marginBottom: '1rem', color: 'var(--healthcare-text-muted)' }}>
                    Devices seen for your account (used for “new device” step-up verification)
                  </p>
                  {loginDevices.length === 0 ? (
                    <p className="empty-state">No login devices recorded</p>
                  ) : (
                    <div className="devices-list">
                      {loginDevices.map((d, idx) => (
                        <div key={idx} className="device-item">
                          <span style={{ fontFamily: 'monospace' }}>{d.deviceId}</span>
                          <span className="device-date">
                            first {d.firstSeenAt ? new Date(d.firstSeenAt).toLocaleString() : '—'} • last {d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : '—'}
                          </span>
                          <span className="appointment-status" style={{ marginLeft: 'auto' }}>
                            {d.verifiedAt ? 'VERIFIED' : (d.blockedAt ? 'BLOCKED' : 'SEEN')}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  <button onClick={loadLoginDevices} className="refresh-btn" style={{ marginTop: '1rem' }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M1 4V10H7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M23 20V14H17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    Refresh
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'settings' && (
            <div className="dashboard-section">
              <div className="section-header">
                <h1>Settings</h1>
              </div>

              <div className="section-grid">
                <div className="healthcare-card">
                  <h2>Issue DID</h2>
                  <p style={{ marginBottom: '1rem', color: 'var(--healthcare-text-muted)' }}>Issue</p>
                  <div className="did-display">
                    <code>{did || 'No DID issued'}</code>
                  </div>
                  <button onClick={handleIssueDID} className="btn-primary" style={{ marginTop: '1rem' }}>
                    Issue DID
                  </button>
                </div>

                <div className="healthcare-card">
                  <h2>Provision Data Key</h2>
                  <p style={{ marginBottom: '1rem', color: 'var(--healthcare-text-muted)' }}>Provision</p>
                  <div className="token-display">
                    <code>Patient token: {patientToken || 'No token'}</code>
                  </div>
                  <button onClick={handleProvisionDataKey} className="btn-primary" style={{ marginTop: '1rem' }}>
                    Provision Data Key
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
