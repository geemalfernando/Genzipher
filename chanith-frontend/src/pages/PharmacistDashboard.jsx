import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import { base64UrlToUint8Array, arrayBufferToBytes } from '../utils/webauthn'
import TotpSetupCard from '../components/TotpSetupCard'
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
  const [biometricVerifiedBannerAt, setBiometricVerifiedBannerAt] = useState(null)

  // Dispense gate (Tier-1 demo)
  const [dispenseRxJson, setDispenseRxJson] = useState('')
  const [dispenseBatchJson, setDispenseBatchJson] = useState('')
  const [dispenseVerifyOut, setDispenseVerifyOut] = useState(null)
  const [dispenseResult, setDispenseResult] = useState(null)
  
  // Dashboard statistics
  const [statistics, setStatistics] = useState({
    totalMedicines: 0,
    totalStockItems: 0,
    lowStockItems: 0,
    expiredItems: 0,
    pendingVerifications: 0
  })

  // Medicines
  const [medicines, setMedicines] = useState([])
  const [medicinesLoaded, setMedicinesLoaded] = useState(false)
  const [medicinesLoading, setMedicinesLoading] = useState(false)
  const [medicineSearch, setMedicineSearch] = useState('')
  const [newMedicine, setNewMedicine] = useState({
    name: '',
    genericName: '',
    manufacturer: '',
    category: 'Antibiotic',
    strengths: '',
    dosageForms: 'Tablet',
    requiresPrescription: true,
  })

  // Stock
  const [stockItems, setStockItems] = useState([])
  const [stockLoaded, setStockLoaded] = useState(false)
  const [stockLoading, setStockLoading] = useState(false)
  const [newStock, setNewStock] = useState({
    medicineId: '',
    quantity: 10,
    unit: 'units',
    expiryDate: '',
    batchId: '',
    location: '',
    minStockLevel: 10,
    notes: '',
  })

  // Quality verification
  const [verifications, setVerifications] = useState([])
  const [verificationsLoaded, setVerificationsLoaded] = useState(false)
  const [verificationsLoading, setVerificationsLoading] = useState(false)
  const [newVerification, setNewVerification] = useState({
    medicineId: '',
    standard: 'USP',
    identity: 'pass',
    potency: 'pass',
    contamination: 'pass',
    notes: '',
  })

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }
    checkBiometricStatus()
  }, [token, navigate])

  useEffect(() => {
    if (!biometricVerified) return
    if (activeTab === 'medicines' && !medicinesLoaded) loadMedicines()
    if (activeTab === 'stock' && !stockLoaded) loadStock()
    if (activeTab === 'quality' && !verificationsLoaded) loadVerifications()
  }, [activeTab, biometricVerified]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!biometricVerifiedBannerAt) return
    const t = setTimeout(() => setBiometricVerifiedBannerAt(null), 8000)
    return () => clearTimeout(t)
  }, [biometricVerifiedBannerAt])

  const checkBiometricStatus = async () => {
    try {
      setLoading(true)
      const [userData, biometricStatus, enrollStatus] = await Promise.all([
        api('/me'),
        api('/pharmacy/biometric-status'),
        api('/biometric/status')
      ])
      
      setUser(userData.user)
      // IMPORTANT: do not rely on /demo/whoami for biometric enrollment.
      // /demo/whoami can be JWT-derived and may not include the latest DB flags.
      // /biometric/status reads DB and self-heals stale flags on the server.
      setBiometricEnrolled(Boolean(enrollStatus?.enrolled) || (Array.isArray(enrollStatus?.biometrics) && enrollStatus.biometrics.length > 0))
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
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to load pharmacy dashboard', 'error')
      }
    }
  }

  const loadMedicines = async () => {
    try {
      setMedicinesLoading(true)
      const qs = new URLSearchParams()
      if (medicineSearch && medicineSearch.trim()) qs.set('search', medicineSearch.trim())
      const data = await api(`/pharmacy/medicines${qs.toString() ? `?${qs.toString()}` : ''}`)
      setMedicines(data.medicines || [])
      setMedicinesLoaded(true)
    } catch (err) {
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to load medicines', 'error')
      }
      setMedicines([])
    } finally {
      setMedicinesLoading(false)
    }
  }

  const createMedicine = async () => {
    try {
      setMedicinesLoading(true)
      const strengths = String(newMedicine.strengths || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      const dosageForms = String(newMedicine.dosageForms || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      const out = await api('/pharmacy/medicines', {
        method: 'POST',
        body: {
          name: newMedicine.name,
          genericName: newMedicine.genericName || undefined,
          manufacturer: newMedicine.manufacturer,
          category: newMedicine.category,
          strengths,
          dosageForms,
          requiresPrescription: Boolean(newMedicine.requiresPrescription),
        },
      })
      toast('Medicine added', 'success')
      setNewMedicine({ ...newMedicine, name: '', genericName: '', strengths: '' })
      setMedicinesLoaded(false)
      await loadMedicines()
      await loadDashboard()
      if (!newStock.medicineId) setNewStock((s) => ({ ...s, medicineId: out.id }))
      if (!newVerification.medicineId) setNewVerification((s) => ({ ...s, medicineId: out.id }))
    } catch (err) {
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to add medicine', 'error')
      }
    } finally {
      setMedicinesLoading(false)
    }
  }

  const loadStock = async () => {
    try {
      setStockLoading(true)
      const data = await api('/pharmacy/stock')
      setStockItems(data.stock || [])
      setStockLoaded(true)
      if (!medicinesLoaded) {
        await loadMedicines()
      }
    } catch (err) {
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to load stock', 'error')
      }
      setStockItems([])
    } finally {
      setStockLoading(false)
    }
  }

  const createStock = async () => {
    if (!newStock.medicineId) return toast('Select a medicine', 'error')
    if (!newStock.expiryDate) return toast('Select an expiry date', 'error')
    try {
      setStockLoading(true)
      await api('/pharmacy/stock', {
        method: 'POST',
        body: {
          medicineId: newStock.medicineId,
          quantity: Number(newStock.quantity),
          unit: newStock.unit || undefined,
          expiryDate: newStock.expiryDate,
          batchId: newStock.batchId || undefined,
          location: newStock.location || undefined,
          minStockLevel: Number(newStock.minStockLevel) || 10,
          notes: newStock.notes || undefined,
        },
      })
      toast('Stock item added', 'success')
      setNewStock({ ...newStock, quantity: 10, expiryDate: '', batchId: '', notes: '' })
      setStockLoaded(false)
      await loadStock()
      await loadDashboard()
    } catch (err) {
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to add stock', 'error')
      }
    } finally {
      setStockLoading(false)
    }
  }

  const loadVerifications = async () => {
    try {
      setVerificationsLoading(true)
      const data = await api('/pharmacy/quality-verifications')
      setVerifications(data.verifications || [])
      setVerificationsLoaded(true)
      if (!medicinesLoaded) {
        await loadMedicines()
      }
    } catch (err) {
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to load verifications', 'error')
      }
      setVerifications([])
    } finally {
      setVerificationsLoading(false)
    }
  }

  const createVerification = async () => {
    if (!newVerification.medicineId) return toast('Select a medicine', 'error')
    if (!newVerification.standard) return toast('Enter a standard', 'error')
    try {
      setVerificationsLoading(true)
      const checks = {
        identity: newVerification.identity,
        potency: newVerification.potency,
        contamination: newVerification.contamination,
      }
      await api('/pharmacy/quality-verification', {
        method: 'POST',
        body: {
          medicineId: newVerification.medicineId,
          standard: newVerification.standard,
          checks,
          notes: newVerification.notes || undefined,
        },
      })
      toast('Quality verification submitted', 'success')
      setNewVerification({ ...newVerification, notes: '' })
      setVerificationsLoaded(false)
      await loadVerifications()
      await loadDashboard()
    } catch (err) {
      if (String(err?.message || '') === 'biometric_verification_required') {
        setBiometricVerified(false)
        toast('Biometric verification required again. Please verify to continue.', 'warning')
      } else {
        toast(err.message || 'Failed to submit verification', 'error')
      }
    } finally {
      setVerificationsLoading(false)
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
        const cid = err?.data?.credentialIdB64u
        toast('This device biometric is already enrolled for another account. Use a different browser profile/device, or ask admin to clear it.', 'warning')
        if (cid) setBiometricError(`credential_exists (${cid})`)
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

      const challengeBuffer = base64UrlToUint8Array(verifyOptions?.challenge)

      const publicKeyCredentialRequestOptions = {
        challenge: challengeBuffer,
        allowCredentials: verifyOptions.allowCredentials.map(cred => ({
          ...cred,
          id: base64UrlToUint8Array(String(cred.id || ''))
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
        rawId: arrayBufferToBytes(assertion.rawId),
        response: {
          authenticatorData: arrayBufferToBytes(assertion.response.authenticatorData),
          clientDataJSON: arrayBufferToBytes(assertion.response.clientDataJSON),
          signature: arrayBufferToBytes(assertion.response.signature),
          userHandle: assertion.response.userHandle ? arrayBufferToBytes(assertion.response.userHandle) : null,
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
        toast('Biometric verified successfully! Loading dashboard…', 'success')
        setActiveTab('dashboard')
        setBiometricVerified(true)
        setBiometricVerifiedBannerAt(Date.now())
        // Auto-refresh: re-check session status and load dashboard + stats immediately.
        // This avoids the user staying on the verification screen with stale content.
        await checkBiometricStatus()
      }
    } catch (err) {
      console.error('Biometric verification error:', err)
      setBiometricError(err.message || 'Biometric verification failed')
      toast(err.message || 'Biometric verification failed', 'error')
    }
  }

  const parseJsonOrThrow = (label, value) => {
    if (!value || !String(value).trim()) throw new Error(`${label}_missing`)
    try {
      return JSON.parse(String(value))
    } catch {
      throw new Error(`${label}_invalid_json`)
    }
  }

  const handleDispenseVerify = async () => {
    try {
      setLoading(true)
      setDispenseResult(null)

      const prescription = parseJsonOrThrow('prescription', dispenseRxJson)
      const batch = parseJsonOrThrow('batch', dispenseBatchJson)

      const [rxVerify, batchVerify] = await Promise.all([
        api('/prescriptions/verify', { method: 'POST', body: { prescription } }),
        api('/batches/verify', { method: 'POST', body: { batch } }),
      ])

      const ok = Boolean(rxVerify?.ok) && Boolean(batchVerify?.ok) && !batchVerify?.expired
      const out = {
        ok,
        prescription: {
          ok: Boolean(rxVerify?.ok),
          checks: rxVerify?.checks || null,
        },
        batch: {
          ok: Boolean(batchVerify?.ok),
          signatureOk: Boolean(batchVerify?.signatureOk),
          expired: Boolean(batchVerify?.expired),
        },
      }
      setDispenseVerifyOut(out)
      toast(ok ? 'Verified ✓' : 'Verification failed ✗', ok ? 'success' : 'error')
    } catch (err) {
      setDispenseVerifyOut(null)
      toast(err.message || 'Verify failed', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleDispenseSubmit = async () => {
    try {
      setLoading(true)
      const prescription = parseJsonOrThrow('prescription', dispenseRxJson)
      const batch = parseJsonOrThrow('batch', dispenseBatchJson)

      const out = await api('/dispense', { method: 'POST', body: { prescription, batch } })
      setDispenseResult(out)
      toast(out?.ok ? 'SAFE TO DISPENSE ✓' : 'BLOCKED ✗', out?.ok ? 'success' : 'error')
    } catch (err) {
      setDispenseResult(null)
      toast(err.message || 'Dispense failed', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleTamperRx = () => {
    try {
      const rx = parseJsonOrThrow('prescription', dispenseRxJson)
      const out = { ...rx, dosage: '999mg' }
      setDispenseRxJson(JSON.stringify(out, null, 2))
      setDispenseVerifyOut(null)
      setDispenseResult(null)
      toast('Tampered: dosage changed to 999mg', 'warning')
    } catch (err) {
      toast(err.message || 'Tamper failed', 'error')
    }
  }

  const handleTamperBatch = () => {
    try {
      const batch = parseJsonOrThrow('batch', dispenseBatchJson)
      const out = { ...batch, batchId: `${batch.batchId || 'BATCH'}-TAMPER` }
      setDispenseBatchJson(JSON.stringify(out, null, 2))
      setDispenseVerifyOut(null)
      setDispenseResult(null)
      toast('Tampered: batchId changed', 'warning')
    } catch (err) {
      toast(err.message || 'Tamper failed', 'error')
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
                    {String(biometricError || '').startsWith('credential_exists (') && (
                      <div style={{ marginLeft: 'auto' }}>
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          onClick={async () => {
                            const match = String(biometricError).match(/\(([^)]+)\)/)
                            const cid = match ? match[1] : ''
                            if (!cid) return toast('No credentialId found', 'warning')
                            await navigator.clipboard.writeText(cid)
                            toast('credentialIdB64u copied (send to admin)', 'success')
                          }}
                        >
                          Copy ID
                        </button>
                      </div>
                    )}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                  {!biometricEnrolled ? (
                    <button onClick={handleEnrollBiometric} className="btn-primary">
                      Enroll Biometric
                    </button>
                  ) : (
                    <>
                      <button onClick={handleVerifyBiometric} className="btn-primary">
                        Start Biometric Verification
                      </button>
                      <button onClick={handleEnrollBiometric} className="btn-secondary" type="button">
                        Enroll this device
                      </button>
                    </>
                  )}
                </div>

                <div style={{ marginTop: '2rem', padding: '1rem', background: 'var(--healthcare-bg)', borderRadius: '8px' }}>
                  <p style={{ fontSize: '0.875rem', color: 'var(--healthcare-text-muted)', margin: 0 }}>
                    <strong>Note:</strong> Fingerprint/FaceID works only after you enroll on the same domain you’re using now.
                    If you enrolled earlier on <span style={{ fontFamily: 'monospace' }}>localhost</span>, click <strong>Enroll this device</strong> on the hosted site to create a new passkey for this domain.
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
          {biometricVerifiedBannerAt && (
            <div className="auth-alert auth-alert-success" style={{ marginBottom: '1rem' }}>
              <div className="alert-icon">✓</div>
              <div className="alert-content">
                <strong>Biometric verified</strong>
                <p style={{ margin: 0 }}>Access granted. Your session is unlocked for pharmacy actions.</p>
              </div>
              <div style={{ marginLeft: 'auto' }}>
                <button
                  type="button"
                  className="btn-secondary btn-sm"
                  onClick={() => setBiometricVerifiedBannerAt(null)}
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}
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
                {user && (!user.mfaEnabled || user.mfaMethod === 'NONE') && (
                  <div style={{ marginBottom: '2rem' }}>
                    <TotpSetupCard title="MFA: Authenticator app (recommended)" onEnabled={checkBiometricStatus} />
                  </div>
                )}

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
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                  <h2>Medicines</h2>
                  <button onClick={loadMedicines} className="btn-secondary" disabled={medicinesLoading}>
                    Refresh
                  </button>
                </div>

                <div style={{ marginTop: '1rem' }} className="form-grid">
                  <div className="form-group">
                    <label className="form-label">Search</label>
                    <input
                      className="form-input"
                      value={medicineSearch}
                      onChange={(e) => setMedicineSearch(e.target.value)}
                      placeholder="amoxicillin, paracetamol…"
                    />
                  </div>
                  <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end' }}>
                    <button onClick={() => { setMedicinesLoaded(false); loadMedicines() }} className="btn-primary" disabled={medicinesLoading}>
                      Search
                    </button>
                  </div>
                </div>

                <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--healthcare-border)' }}>
                  <h3 style={{ marginBottom: '0.75rem' }}>Add medicine</h3>
                  <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div className="form-group">
                      <label className="form-label">Name *</label>
                      <input className="form-input" value={newMedicine.name} onChange={(e) => setNewMedicine({ ...newMedicine, name: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Generic name</label>
                      <input className="form-input" value={newMedicine.genericName} onChange={(e) => setNewMedicine({ ...newMedicine, genericName: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Manufacturer *</label>
                      <input className="form-input" value={newMedicine.manufacturer} onChange={(e) => setNewMedicine({ ...newMedicine, manufacturer: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Category *</label>
                      <input className="form-input" value={newMedicine.category} onChange={(e) => setNewMedicine({ ...newMedicine, category: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Strengths (comma)</label>
                      <input className="form-input" value={newMedicine.strengths} onChange={(e) => setNewMedicine({ ...newMedicine, strengths: e.target.value })} placeholder="500mg, 250mg" />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Dosage forms (comma)</label>
                      <input className="form-input" value={newMedicine.dosageForms} onChange={(e) => setNewMedicine({ ...newMedicine, dosageForms: e.target.value })} placeholder="Tablet, Capsule" />
                    </div>
                    <div className="form-group">
                      <label className="form-checkbox">
                        <input
                          type="checkbox"
                          checked={Boolean(newMedicine.requiresPrescription)}
                          onChange={(e) => setNewMedicine({ ...newMedicine, requiresPrescription: e.target.checked })}
                        />
                        <span>Requires prescription</span>
                      </label>
                    </div>
                    <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end' }}>
                      <button onClick={createMedicine} className="btn-primary" disabled={medicinesLoading}>
                        {medicinesLoading ? 'Saving…' : 'Add'}
                      </button>
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--healthcare-border)' }}>
                  <h3 style={{ marginBottom: '0.75rem' }}>List</h3>
                  {medicinesLoading ? (
                    <p className="empty-state">Loading…</p>
                  ) : medicines.length === 0 ? (
                    <p className="empty-state">No medicines yet.</p>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Name</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Manufacturer</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Category</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Strengths</th>
                          </tr>
                        </thead>
                        <tbody>
                          {medicines.slice(0, 100).map((m) => (
                            <tr key={m.id} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                              <td style={{ padding: '0.75rem' }}>
                                <div style={{ fontWeight: 700 }}>{m.name}</div>
                                <div style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>{m.id}</div>
                              </td>
                              <td style={{ padding: '0.75rem' }}>{m.manufacturer}</td>
                              <td style={{ padding: '0.75rem' }}>{m.category}</td>
                              <td style={{ padding: '0.75rem', color: 'var(--healthcare-text-muted)' }}>
                                {(m.strengths || []).slice(0, 3).join(', ') || '—'}
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

            {activeTab === 'stock' && (
              <div className="healthcare-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                  <h2>Stock</h2>
                  <button onClick={loadStock} className="btn-secondary" disabled={stockLoading}>
                    Refresh
                  </button>
                </div>

                <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--healthcare-border)' }}>
                  <h3 style={{ marginBottom: '0.75rem' }}>Add stock</h3>
                  <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div className="form-group">
                      <label className="form-label">Medicine *</label>
                      <select className="form-input" value={newStock.medicineId} onChange={(e) => setNewStock({ ...newStock, medicineId: e.target.value })}>
                        <option value="">Select…</option>
                        {medicines.map((m) => (
                          <option key={m.id} value={m.id}>
                            {m.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Quantity *</label>
                      <input type="number" className="form-input" value={newStock.quantity} onChange={(e) => setNewStock({ ...newStock, quantity: e.target.value })} min="0" />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Expiry date *</label>
                      <input type="date" className="form-input" value={newStock.expiryDate} onChange={(e) => setNewStock({ ...newStock, expiryDate: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Min stock level</label>
                      <input type="number" className="form-input" value={newStock.minStockLevel} onChange={(e) => setNewStock({ ...newStock, minStockLevel: e.target.value })} min="0" />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Batch ID</label>
                      <input className="form-input" value={newStock.batchId} onChange={(e) => setNewStock({ ...newStock, batchId: e.target.value })} placeholder="optional" />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Location</label>
                      <input className="form-input" value={newStock.location} onChange={(e) => setNewStock({ ...newStock, location: e.target.value })} placeholder="Shelf A3" />
                    </div>
                    <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                      <label className="form-label">Notes</label>
                      <input className="form-input" value={newStock.notes} onChange={(e) => setNewStock({ ...newStock, notes: e.target.value })} placeholder="optional" />
                    </div>
                    <div className="form-group">
                      <button onClick={createStock} className="btn-primary" disabled={stockLoading}>
                        {stockLoading ? 'Saving…' : 'Add'}
                      </button>
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--healthcare-border)' }}>
                  <h3 style={{ marginBottom: '0.75rem' }}>List</h3>
                  {stockLoading ? (
                    <p className="empty-state">Loading…</p>
                  ) : stockItems.length === 0 ? (
                    <p className="empty-state">No stock items yet.</p>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Medicine</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Qty</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Status</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Expiry</th>
                          </tr>
                        </thead>
                        <tbody>
                          {stockItems.slice(0, 200).map((s) => (
                            <tr key={s.id} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                              <td style={{ padding: '0.75rem' }}>
                                <div style={{ fontWeight: 700 }}>{s.medicineName || s.medicineId}</div>
                                <div style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>{s.id}</div>
                              </td>
                              <td style={{ padding: '0.75rem' }}>
                                {s.quantity} {s.unit || ''}
                              </td>
                              <td style={{ padding: '0.75rem' }}>
                                <span className="status-badge">{s.status || '—'}</span>
                              </td>
                              <td style={{ padding: '0.75rem', fontFamily: 'monospace', color: 'var(--healthcare-text-muted)' }}>
                                {s.expiryDate || '—'}
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

            {activeTab === 'quality' && (
              <div className="healthcare-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                  <h2>Quality verification</h2>
                  <button onClick={loadVerifications} className="btn-secondary" disabled={verificationsLoading}>
                    Refresh
                  </button>
                </div>

                <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--healthcare-border)' }}>
                  <h3 style={{ marginBottom: '0.75rem' }}>Submit verification</h3>
                  <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div className="form-group">
                      <label className="form-label">Medicine *</label>
                      <select className="form-input" value={newVerification.medicineId} onChange={(e) => setNewVerification({ ...newVerification, medicineId: e.target.value })}>
                        <option value="">Select…</option>
                        {medicines.map((m) => (
                          <option key={m.id} value={m.id}>
                            {m.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Standard *</label>
                      <input className="form-input" value={newVerification.standard} onChange={(e) => setNewVerification({ ...newVerification, standard: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Identity</label>
                      <select className="form-input" value={newVerification.identity} onChange={(e) => setNewVerification({ ...newVerification, identity: e.target.value })}>
                        <option value="pass">pass</option>
                        <option value="fail">fail</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Potency</label>
                      <select className="form-input" value={newVerification.potency} onChange={(e) => setNewVerification({ ...newVerification, potency: e.target.value })}>
                        <option value="pass">pass</option>
                        <option value="fail">fail</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Contamination</label>
                      <select className="form-input" value={newVerification.contamination} onChange={(e) => setNewVerification({ ...newVerification, contamination: e.target.value })}>
                        <option value="pass">pass</option>
                        <option value="fail">fail</option>
                      </select>
                    </div>
                    <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                      <label className="form-label">Notes</label>
                      <input className="form-input" value={newVerification.notes} onChange={(e) => setNewVerification({ ...newVerification, notes: e.target.value })} placeholder="optional" />
                    </div>
                    <div className="form-group">
                      <button onClick={createVerification} className="btn-primary" disabled={verificationsLoading}>
                        {verificationsLoading ? 'Saving…' : 'Submit'}
                      </button>
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--healthcare-border)' }}>
                  <h3 style={{ marginBottom: '0.75rem' }}>Recent verifications</h3>
                  {verificationsLoading ? (
                    <p className="empty-state">Loading…</p>
                  ) : verifications.length === 0 ? (
                    <p className="empty-state">No verifications yet.</p>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr style={{ borderBottom: '2px solid var(--healthcare-border)' }}>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Time</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Medicine</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Standard</th>
                            <th style={{ padding: '0.75rem', textAlign: 'left', fontWeight: 600 }}>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {verifications.slice(0, 200).map((v) => (
                            <tr key={v.id} style={{ borderBottom: '1px solid var(--healthcare-border)' }}>
                              <td style={{ padding: '0.75rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                                {v.verificationDate ? new Date(v.verificationDate).toLocaleString() : '—'}
                              </td>
                              <td style={{ padding: '0.75rem' }}>
                                <div style={{ fontFamily: 'monospace', color: 'var(--healthcare-text-muted)', fontSize: '0.8125rem' }}>{v.medicineId}</div>
                              </td>
                              <td style={{ padding: '0.75rem' }}>{v.standard}</td>
                              <td style={{ padding: '0.75rem' }}>
                                <span className="status-badge">{v.overallStatus || '—'}</span>
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

            {activeTab === 'dispense' && (
              <div className="healthcare-card">
                <h2>Verify + Dispense Gate</h2>
                <p style={{ color: 'var(--healthcare-text-muted)', marginBottom: '1.25rem' }}>
                  Paste/scan the signed prescription and signed batch. The system verifies both and either allows dispensing or blocks it.
                </p>

                {dispenseResult && (
                  <div
                    style={{
                      padding: '1rem',
                      borderRadius: '10px',
                      marginBottom: '1.25rem',
                      background: dispenseResult.ok ? 'var(--healthcare-success-bg)' : 'var(--healthcare-error-bg)',
                      border: `1px solid ${dispenseResult.ok ? 'var(--healthcare-success)' : 'var(--healthcare-danger)'}`,
                    }}
                  >
                    <div style={{ fontSize: '1.1rem', fontWeight: 800 }}>
                      {dispenseResult.ok ? 'SAFE TO DISPENSE ✓' : 'BLOCKED ✗'}
                    </div>
                    <div style={{ marginTop: '0.5rem', color: 'var(--healthcare-text-muted)', fontSize: '0.9rem' }}>
                      {dispenseResult.ok
                        ? 'Dispense recorded and audited.'
                        : 'Do not dispense. Possible tamper/invalid prescription or batch.'}
                    </div>
                  </div>
                )}

                <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Prescription JSON</label>
                    <textarea
                      className="form-input"
                      rows={10}
                      value={dispenseRxJson}
                      onChange={(e) => setDispenseRxJson(e.target.value)}
                      placeholder='Paste signed prescription JSON here…'
                      style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                    />
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
                      <button onClick={handleDispenseVerify} className="btn-secondary" disabled={loading}>
                        Verify
                      </button>
                      <button onClick={handleTamperRx} className="btn-danger" type="button" disabled={!dispenseRxJson}>
                        Tamper dosage
                      </button>
                    </div>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Batch JSON</label>
                    <textarea
                      className="form-input"
                      rows={10}
                      value={dispenseBatchJson}
                      onChange={(e) => setDispenseBatchJson(e.target.value)}
                      placeholder='Paste signed batch JSON here…'
                      style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                    />
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
                      <button onClick={handleDispenseVerify} className="btn-secondary" disabled={loading}>
                        Verify
                      </button>
                      <button onClick={handleTamperBatch} className="btn-danger" type="button" disabled={!dispenseBatchJson}>
                        Tamper batchId
                      </button>
                    </div>
                  </div>
                </div>

                {dispenseVerifyOut && (
                  <div style={{ marginTop: '1.25rem', padding: '0.75rem', background: 'var(--healthcare-bg)', borderRadius: '10px' }}>
                    <div style={{ fontWeight: 700, marginBottom: '0.5rem' }}>
                      {dispenseVerifyOut.ok ? 'Verified ✓' : 'Verification failed ✗'}
                    </div>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: '0.85rem' }}>
                      {JSON.stringify(dispenseVerifyOut, null, 2)}
                    </pre>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '1.25rem' }}>
                  <button onClick={handleDispenseSubmit} className="btn-primary" disabled={loading}>
                    {loading ? 'Processing…' : 'Dispense'}
                  </button>
                  <button
                    onClick={() => {
                      setDispenseRxJson('')
                      setDispenseBatchJson('')
                      setDispenseVerifyOut(null)
                      setDispenseResult(null)
                    }}
                    className="btn-secondary"
                    type="button"
                    disabled={loading}
                  >
                    Clear
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
