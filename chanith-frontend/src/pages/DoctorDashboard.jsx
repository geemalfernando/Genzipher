import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import AlertsList from '../components/AlertsList'
import TotpSetupCard from '../components/TotpSetupCard'
import '../styles/PatientDashboard.css'

export default function DoctorDashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [activeSection, setActiveSection] = useState('dashboard')
  
  // Patient selection
  const [patients, setPatients] = useState([])
  const [selectedPatient, setSelectedPatient] = useState('')
  const [patientSearchQuery, setPatientSearchQuery] = useState('')
  const [assignedCases, setAssignedCases] = useState([])
  
  // Medicine search
  const [medicineSearchQuery, setMedicineSearchQuery] = useState('')
  const [medicines, setMedicines] = useState([])
  const [selectedMedicines, setSelectedMedicines] = useState([])
  
  // Prescription
  const [signedPrescription, setSignedPrescription] = useState('')
  const [verificationResult, setVerificationResult] = useState('')
  const [user, setUser] = useState(null)
  const [recentPrescriptions, setRecentPrescriptions] = useState([])
  const [alerts, setAlerts] = useState([])

  // Patient prescription history (for selected patient)
  const [patientRxHistory, setPatientRxHistory] = useState(null)

  // Appointments (doctor view)
  const [doctorAppointments, setDoctorAppointments] = useState([])
  const [apptFilter, setApptFilter] = useState({ status: '', date: '' })

  // Vitals viewer
  const [selectedPatientToken, setSelectedPatientToken] = useState('')
  const [vitalsRecords, setVitalsRecords] = useState([])
  const [vitalsBreakGlass, setVitalsBreakGlass] = useState(false)

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    loadInitialData()
  }, [token, navigate])

  const loadInitialData = async () => {
    try {
      setLoading(true)
      await Promise.all([
        loadUserData(),
        loadPatients(),
        loadMedicines()
      ])
      await loadDoctorDashboard()
    } catch (err) {
      console.error('Load initial data error:', err)
    } finally {
      setLoading(false)
    }
  }

  const loadUserData = async () => {
    try {
      const data = await api('/me')
      setUser(data.user)
    } catch (err) {
      console.error('User data load error:', err)
    }
  }

  const loadPatients = async () => {
    try {
      const data = await api('/demo/users')
      const patientUsers = data.users?.filter(u => u.role === 'patient') || []
      setPatients(patientUsers)
      if (patientUsers.length > 0 && !selectedPatient) {
        setSelectedPatient(patientUsers[0].id)
      }
    } catch (err) {
      console.error('Patients load error:', err)
      setPatients([])
    }
  }

  const loadDoctorDashboard = async () => {
    try {
      const [casesData, rxData, alertsData] = await Promise.all([
        api('/doctor/cases'),
        api('/doctor/prescriptions?limit=25'),
        api('/alerts/feed?windowHours=24&limit=25'),
      ])
      setAssignedCases(casesData.patients || [])
      setRecentPrescriptions(rxData.prescriptions || [])
      setAlerts(alertsData.alerts || [])
      if (!selectedPatientToken && (casesData.patients || []).length > 0) {
        setSelectedPatientToken(casesData.patients[0].patientToken)
      }
    } catch (err) {
      console.error('Doctor dashboard load error:', err)
      setAssignedCases([])
      setRecentPrescriptions([])
      setAlerts([])
    }
  }

  const loadPatientPrescriptionHistory = async (patientUserId) => {
    if (!patientUserId) {
      setPatientRxHistory(null)
      return
    }
    try {
      const data = await api(`/doctor/patient-prescriptions?patientUserId=${encodeURIComponent(patientUserId)}&limit=100`)
      setPatientRxHistory(data)
    } catch (err) {
      console.error('Patient prescription history load error:', err)
      setPatientRxHistory(null)
    }
  }

  useEffect(() => {
    if (!token) return
    loadPatientPrescriptionHistory(selectedPatient)
  }, [selectedPatient, token])

  const loadVitals = async ({ patientToken, breakGlass }) => {
    if (!patientToken) return
    try {
      setLoading(true)
      const data = await api(`/vitals/${encodeURIComponent(patientToken)}`, {
        headers: breakGlass ? { 'x-break-glass': 'true' } : {},
      })
      setVitalsRecords(data.records || [])
      toast(breakGlass ? 'Emergency access recorded' : 'Vitals loaded', breakGlass ? 'warning' : 'success')
    } catch (err) {
      toast(err.message || 'Failed to load vitals', 'error')
      setVitalsRecords([])
    } finally {
      setLoading(false)
    }
  }

  const loadMedicines = async () => {
    try {
      // Try to get medicines from pharmacy endpoint (might require auth)
      // If it fails, doctors can still add medicines manually by name
      try {
        const data = await api('/pharmacy/medicines')
        setMedicines(data.medicines || [])
      } catch (err) {
        // Silently fail - doctors can still type medicine names manually
        // This is expected since doctors don't have pharmacy role access
        setMedicines([])
      }
    } catch (err) {
      // Silently fail - doctors can still type medicine names manually
      setMedicines([])
    }
  }

  const loadDoctorAppointments = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (apptFilter.status) params.set('status', apptFilter.status)
      if (apptFilter.date) params.set('date', apptFilter.date)
      const qs = params.toString()
      const data = await api(`/doctor/appointments${qs ? `?${qs}` : ''}`)
      setDoctorAppointments(data.appointments || [])
      toast(`Loaded ${data.count || 0} appointments`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to load appointments', 'error')
      setDoctorAppointments([])
    } finally {
      setLoading(false)
    }
  }

  const searchPatients = async () => {
    if (!patientSearchQuery || patientSearchQuery.trim().length < 2) {
      toast('Search query must be at least 2 characters', 'error')
      return
    }
    try {
      const data = await api(`/doctors/patients/search?query=${encodeURIComponent(patientSearchQuery)}`)
      setPatients(data.patients || [])
      toast(`Found ${data.count || 0} patients`, 'success')
    } catch (err) {
      toast(err.message || 'Failed to search patients', 'error')
    }
  }

  const handleAddMedicine = () => {
    if (!medicineSearchQuery.trim()) {
      toast('Please enter a medicine name', 'error')
      return
    }
    
    const medicine = medicines.find(m => 
      m.name.toLowerCase().includes(medicineSearchQuery.toLowerCase()) ||
      m.genericName?.toLowerCase().includes(medicineSearchQuery.toLowerCase())
    )

    if (!medicine) {
      // Allow adding medicine by name even if not in database
      const newMedicine = {
        id: `MED-${Date.now()}`,
        name: medicineSearchQuery,
        dosage: '',
        durationDays: 7
      }
      setSelectedMedicines([...selectedMedicines, newMedicine])
      setMedicineSearchQuery('')
      toast('Medicine added. Please fill dosage and duration.', 'success')
      return
    }

    // Check if already added
    if (selectedMedicines.find(m => m.id === medicine.id)) {
      toast('Medicine already added', 'warning')
      return
    }

    setSelectedMedicines([...selectedMedicines, {
      id: medicine.id,
      name: medicine.name,
      dosage: medicine.strengths?.[0] || '',
      durationDays: 7
    }])
    setMedicineSearchQuery('')
    toast('Medicine added', 'success')
  }

  const handleRemoveMedicine = (index) => {
    setSelectedMedicines(selectedMedicines.filter((_, i) => i !== index))
  }

  const handleUpdateMedicine = (index, field, value) => {
    const updated = [...selectedMedicines]
    updated[index] = { ...updated[index], [field]: value }
    setSelectedMedicines(updated)
  }

  const handleCreatePrescription = async () => {
    if (!selectedPatient) {
      toast('Please select a patient', 'error')
      return
    }
    if (selectedMedicines.length === 0) {
      toast('Please add at least one medicine', 'error')
      return
    }

    // Validate all medicines have dosage and duration
    for (let i = 0; i < selectedMedicines.length; i++) {
      const med = selectedMedicines[i]
      if (!med.dosage || !med.durationDays) {
        toast(`Please fill dosage and duration for ${med.name}`, 'error')
        return
      }
    }

    try {
      setLoading(true)

      // Backend contract in this project: one signed Rx per medicine
      // POST /prescriptions expects { patientUserId, medicineId, dosage, durationDays }
      const created = []
      for (const med of selectedMedicines) {
        const rx = await api('/prescriptions', {
          method: 'POST',
          body: {
            patientUserId: selectedPatient,
            medicineId: med.id || med.name,
            dosage: med.dosage,
            durationDays: parseInt(med.durationDays) || 7,
          },
        })
        created.push(rx)
      }

      setSignedPrescription(JSON.stringify(created.length === 1 ? created[0] : created, null, 2))
      setVerificationResult('')
      toast(created.length === 1 ? 'Prescription Secured & Signed ✓' : `Prescriptions Secured & Signed ✓ (${created.length})`, 'success')
      await loadDoctorDashboard()
    } catch (err) {
      toast(err.message || 'Failed to create prescription', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleCopyPrescription = () => {
    if (!signedPrescription) {
      toast('No prescription to copy', 'warning')
      return
    }
    navigator.clipboard.writeText(signedPrescription)
    toast('Prescription copied to clipboard', 'success')
  }

  const handleTamperPrescription = () => {
    if (!signedPrescription) {
      toast('No prescription to tamper', 'warning')
      return
    }
    try {
      const parsed = JSON.parse(signedPrescription)
      const arr = Array.isArray(parsed) ? parsed : [parsed]
      if (!arr.length) throw new Error('empty')
      // Tamper the first Rx dosage
      arr[0].dosage = '999mg'
      setSignedPrescription(JSON.stringify(Array.isArray(parsed) ? arr : arr[0], null, 2))
      setVerificationResult('')
      toast('Prescription tampered (dosage changed to 999mg)', 'warning')
    } catch (err) {
      toast('Failed to tamper prescription', 'error')
    }
  }

  const handleVerifyPrescription = async () => {
    if (!signedPrescription) {
      toast('No prescription to verify', 'warning')
      return
    }
    try {
      const parsed = JSON.parse(signedPrescription)
      const arr = Array.isArray(parsed) ? parsed : [parsed]
      const results = []
      for (const rx of arr) {
        const r = await api('/prescriptions/verify', { method: 'POST', body: { prescription: rx } })
        results.push({ id: rx.id || null, ok: r.ok, checks: r.checks })
      }
      const allOk = results.every((r) => r.ok)
      setVerificationResult(JSON.stringify({ ok: allOk, results }, null, 2))
      toast(allOk ? 'Verified ✓' : 'Verification failed ✗', allOk ? 'success' : 'error')
    } catch (err) {
      toast(err.message || 'Failed to verify prescription', 'error')
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const handleRequestAccountDeletion = async () => {
    try {
      await api('/account/delete-request', { method: 'POST' })
      toast('Deletion request sent to admin for approval.', 'warning')
    } catch (err) {
      toast(err.message || 'Failed to request deletion', 'error')
    }
  }

  if (loading && !user) {
    return (
      <div className="patient-dashboard">
        <div className="loading-state">
          <p>Loading...</p>
        </div>
      </div>
    )
  }

  const selectedPatientData = patients.find(p => p.id === selectedPatient)

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
            <p>Doctor Portal</p>
          </div>
        </div>

        <nav className="patient-sidebar-nav">
          <button
            className={`nav-item ${activeSection === 'prescriptions' ? 'active' : ''}`}
            onClick={() => setActiveSection('prescriptions')}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2"/>
              <path d="M16 13H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <path d="M16 17H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>Prescriptions</span>
          </button>
          <button
            className={`nav-item ${activeSection === 'account' ? 'active' : ''}`}
            onClick={() => setActiveSection('account')}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M20 21V19C20 17.9391 19.5786 16.9217 18.8284 16.1716C18.0783 15.4214 17.0609 15 16 15H8C6.93913 15 5.92172 15.4214 5.17157 16.1716C4.42143 16.9217 4 17.9391 4 19V21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M12 11C14.2091 11 16 9.20914 16 7C16 4.79086 14.2091 3 12 3C9.79086 3 8 4.79086 8 7C8 9.20914 9.79086 11 12 11Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span>Account</span>
          </button>
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
          {activeSection === 'prescriptions' && (
          <div className="dashboard-section">
            <div className="section-header">
              <div>
                <h1>Role Workspace</h1>
                <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.9375rem' }}>
                  Current role: {user?.role || 'doctor'}
                </p>
              </div>
            </div>

            {user && (!user.mfaEnabled || user.mfaMethod === 'NONE') && (
              <div style={{ marginBottom: '2rem' }}>
                <TotpSetupCard title="MFA: Authenticator app (recommended)" onEnabled={loadUserData} />
              </div>
            )}

            <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
              <h2>Doctor: Sign Prescription</h2>

              <div className="healthcare-card" style={{ marginTop: '1rem', background: 'var(--healthcare-bg)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                  <div>
                    <h3 style={{ marginTop: 0, marginBottom: '0.25rem' }}>Alert Center</h3>
                    <p style={{ margin: 0, color: 'var(--healthcare-text-muted)' }}>
                      High-signal security events related to your activity.
                    </p>
                  </div>
                  <button className="btn-secondary btn-sm" type="button" onClick={loadDoctorDashboard} disabled={loading}>
                    Refresh
                  </button>
                </div>
                <AlertsList alerts={alerts} limit={10} showType={false} compact />
              </div>
              
              <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
                <div className="form-group" style={{ flex: '1', minWidth: '200px' }}>
                  <label className="form-group-label">Patient</label>
                  <select
                    value={selectedPatient}
                    onChange={(e) => setSelectedPatient(e.target.value)}
                    className="form-input"
                  >
                    <option value="">Select a patient...</option>
                    {patients.map(patient => (
                      <option key={patient.id} value={patient.id}>
                        {patient.username} ({patient.id})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-group" style={{ flex: '2', minWidth: '250px' }}>
                  <label className="form-group-label">Search Medicine</label>
                  <input
                    type="text"
                    className="form-input"
                    value={medicineSearchQuery}
                    onChange={(e) => setMedicineSearchQuery(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleAddMedicine()}
                    placeholder="Type to search medicines (e.g., Amoxicillin, Paracetamol...)"
                  />
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
                  <button onClick={handleAddMedicine} className="btn-primary" style={{ whiteSpace: 'nowrap' }}>
                    Create Rx
                  </button>
                </div>
              </div>

              <div className="healthcare-card" style={{ marginTop: '1.25rem', background: 'var(--healthcare-bg)' }}>
                <h3 style={{ marginTop: 0 }}>Patient prescriptions</h3>
                <p style={{ color: 'var(--healthcare-text-muted)', marginTop: '0.25rem' }}>
                  Ongoing prescriptions are valid and not yet used. Past prescriptions are used or expired.
                </p>

                {!selectedPatient ? (
                  <p className="empty-state">Select a patient to view prescription history.</p>
                ) : !patientRxHistory ? (
                  <p className="empty-state">Loading history…</p>
                ) : (
                  <div className="section-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div className="healthcare-card" style={{ margin: 0 }}>
                      <h4 style={{ marginTop: 0 }}>Ongoing ({patientRxHistory.ongoingCount || 0})</h4>
                      {(patientRxHistory.ongoing || []).length === 0 ? (
                        <p className="empty-state">No ongoing prescriptions.</p>
                      ) : (
                        <div className="appointments-list">
                          {patientRxHistory.ongoing.map((it) => (
                            <div key={it.prescription?.id} className="appointment-item">
                              <div className="appointment-header">
                                <span className="appointment-status">VALID</span>
                                <span className="appointment-date">
                                  {it.prescription?.issuedAt ? new Date(it.prescription.issuedAt).toLocaleString() : '—'}
                                </span>
                              </div>
                              <div className="appointment-details">
                                <p><strong>Medicine:</strong> {it.prescription?.medicineId || '—'}</p>
                                <p><strong>Dosage:</strong> {it.prescription?.dosage || '—'}</p>
                                <p><strong>Expires:</strong> {it.prescription?.expiry ? new Date(it.prescription.expiry).toLocaleString() : '—'}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="healthcare-card" style={{ margin: 0 }}>
                      <h4 style={{ marginTop: 0 }}>Past ({patientRxHistory.pastCount || 0})</h4>
                      {(patientRxHistory.past || []).length === 0 ? (
                        <p className="empty-state">No past prescriptions.</p>
                      ) : (
                        <div className="appointments-list">
                          {patientRxHistory.past.map((it) => (
                            <div key={it.prescription?.id} className="appointment-item">
                              <div className="appointment-header">
                                <span className="appointment-status">{it.status || 'PAST'}</span>
                                <span className="appointment-date">
                                  {it.usedAt ? `Used ${new Date(it.usedAt).toLocaleString()}` : (it.prescription?.expiry ? `Expired ${new Date(it.prescription.expiry).toLocaleString()}` : '—')}
                                </span>
                              </div>
                              <div className="appointment-details">
                                <p><strong>Medicine:</strong> {it.prescription?.medicineId || '—'}</p>
                                <p><strong>Dosage:</strong> {it.prescription?.dosage || '—'}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <div style={{ marginBottom: '1.25rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <div className="form-group" style={{ flex: 1, minWidth: '220px' }}>
                  <label className="form-group-label">Search patients</label>
                  <input
                    type="text"
                    className="form-input"
                    value={patientSearchQuery}
                    onChange={(e) => setPatientSearchQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && searchPatients()}
                    placeholder="Type at least 2 characters..."
                  />
                </div>
                <button onClick={searchPatients} className="btn-secondary" style={{ whiteSpace: 'nowrap' }}>
                  Search Patients
                </button>
              </div>
            </div>

            <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
              <h2>Selected Medicines</h2>
              
              {selectedMedicines.length === 0 ? (
                <p className="empty-state">No medicines added. Search and select medicines above.</p>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                        <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Medicine Name</th>
                        <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Dosage</th>
                        <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Duration (days)</th>
                        <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedMedicines.map((medicine, index) => (
                        <tr key={index} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                          <td style={{ padding: '1rem' }}>{medicine.name}</td>
                          <td style={{ padding: '1rem' }}>
                            <input
                              type="text"
                              value={medicine.dosage}
                              onChange={(e) => handleUpdateMedicine(index, 'dosage', e.target.value)}
                              placeholder="e.g., 500mg"
                              className="form-input"
                              style={{ width: '100%', minWidth: '120px' }}
                            />
                          </td>
                          <td style={{ padding: '1rem' }}>
                            <input
                              type="number"
                              value={medicine.durationDays}
                              onChange={(e) => handleUpdateMedicine(index, 'durationDays', e.target.value)}
                              placeholder="7"
                              className="form-input"
                              style={{ width: '100%', minWidth: '100px' }}
                              min="1"
                            />
                          </td>
                          <td style={{ padding: '1rem' }}>
                            <button
                              onClick={() => handleRemoveMedicine(index)}
                              className="btn-danger"
                              style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
                            >
                              Remove
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <button
                onClick={handleCreatePrescription}
                className="btn-primary"
                disabled={selectedMedicines.length === 0 || loading}
                style={{ marginTop: '1.5rem', width: '100%' }}
              >
                {loading ? 'Creating...' : 'Create + Sign Prescription'}
              </button>
            </div>

            <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h2>Signed Prescription JSON</h2>
                <div style={{ display: 'flex', gap: '0.75rem' }}>
                  <button onClick={handleCopyPrescription} className="btn-secondary" disabled={!signedPrescription}>
                    Copy
                  </button>
                  <button onClick={handleTamperPrescription} className="btn-danger" disabled={!signedPrescription}>
                    Tamper
                  </button>
                  <button onClick={handleVerifyPrescription} className="btn-secondary" disabled={!signedPrescription}>
                    Verify
                  </button>
                </div>
              </div>
              <textarea
                value={signedPrescription || 'Create an Rx to populate...'}
                readOnly
                className="form-input"
                style={{ 
                  width: '100%', 
                  minHeight: '200px', 
                  fontFamily: 'Monaco, Courier New, monospace',
                  fontSize: '0.875rem',
                  backgroundColor: signedPrescription ? 'var(--healthcare-bg)' : 'var(--healthcare-card)'
                }}
              />
            </div>

            <div className="healthcare-card">
              <h2>Verification result...</h2>
              <textarea
                value={verificationResult || ''}
                readOnly
                className="form-input"
                style={{ 
                  width: '100%', 
                  minHeight: '150px', 
                  fontFamily: 'Monaco, Courier New, monospace',
                  fontSize: '0.875rem',
                  backgroundColor: verificationResult ? 'var(--healthcare-bg)' : 'var(--healthcare-card)'
                }}
                placeholder="Verify a prescription to see results..."
              />
            </div>
          </div>
          )}

          {activeSection === 'appointments' && (
            <div className="dashboard-section">
              <div className="section-header">
                <div>
                  <h1>Appointments</h1>
                  <p style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.9375rem' }}>
                    Patients can book appointments; doctors see assigned appointments here.
                  </p>
                </div>
              </div>

              <div className="healthcare-card" style={{ marginBottom: '2rem' }}>
                <h2>My appointments</h2>
                <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Status (optional)</label>
                    <select
                      className="form-input"
                      value={apptFilter.status}
                      onChange={(e) => setApptFilter((v) => ({ ...v, status: e.target.value }))}
                    >
                      <option value="">All</option>
                      <option value="REQUESTED">REQUESTED</option>
                      <option value="CONFIRMED">CONFIRMED</option>
                      <option value="CANCELLED">CANCELLED</option>
                      <option value="COMPLETED">COMPLETED</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Date (optional)</label>
                    <input
                      type="date"
                      className="form-input"
                      value={apptFilter.date}
                      onChange={(e) => setApptFilter((v) => ({ ...v, date: e.target.value }))}
                    />
                  </div>
                </div>

                <button onClick={loadDoctorAppointments} className="btn-primary" disabled={loading}>
                  {loading ? 'Loading…' : 'Load appointments'}
                </button>

                {doctorAppointments.length === 0 ? (
                  <p className="empty-state" style={{ marginTop: '1rem' }}>
                    No appointments found.
                  </p>
                ) : (
                  <div style={{ marginTop: '1rem', overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                          <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>When</th>
                          <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Patient</th>
                          <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Status</th>
                          <th style={{ padding: '1rem', textAlign: 'left', fontWeight: 600 }}>Notes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {doctorAppointments.map((a) => (
                          <tr key={a.id} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                            <td style={{ padding: '1rem', fontSize: '0.9rem' }}>
                              {a.appointmentDate} {a.appointmentTime ? `@ ${a.appointmentTime}` : ''}
                            </td>
                            <td style={{ padding: '1rem', fontSize: '0.9rem' }}>
                              {a.patient?.username ? `${a.patient.username} ` : ''}
                              <span style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)' }}>
                                ({a.patientId})
                              </span>
                            </td>
                            <td style={{ padding: '1rem', fontSize: '0.9rem' }}>
                              <span className="appointment-status">{a.status}</span>
                            </td>
                            <td style={{ padding: '1rem', fontSize: '0.9rem', color: 'var(--healthcare-text-muted)' }}>
                              {a.notes || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeSection === 'account' && (
            <div className="dashboard-section">
              <div className="section-header">
                <h1>Account</h1>
              </div>
              <div className="healthcare-card">
                <h2>Account deletion</h2>
                <p style={{ marginBottom: '1rem', color: 'var(--healthcare-text-muted)' }}>
                  Request deletion. An admin must approve before your account is removed.
                </p>
                <button onClick={handleRequestAccountDeletion} className="btn-danger" type="button">
                  Request deletion
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
