import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../utils/AuthContext'
import { api, toast } from '../utils/api'
import PatientDashboard from './PatientDashboard'
import DoctorDashboard from './DoctorDashboard'
import PharmacistDashboard from './PharmacistDashboard'
import AdminDashboard from './AdminDashboard'
import ManufacturerDashboard from './ManufacturerDashboard'

export default function Dashboard() {
  const navigate = useNavigate()
  const { token, logout } = useAuth()
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!token) {
      navigate('/login')
      return
    }

    loadUserData()
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
    } finally {
      setLoading(false)
    }
  }

  // Route to role-specific dashboards
  if (loading) {
    return (
      <div className="dashboard-container">
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
          <p>Loading...</p>
        </div>
      </div>
    )
  }

  // Show patient dashboard for patients
  if (user && user.role === 'patient') {
    return <PatientDashboard />
  }

  // Show doctor dashboard for doctors
  if (user && user.role === 'doctor') {
    return <DoctorDashboard />
  }

  // Show pharmacist dashboard for pharmacy users
  if (user && user.role === 'pharmacy') {
    return <PharmacistDashboard />
  }

  // Show admin dashboard for admin users
  if (user && user.role === 'admin') {
    return <AdminDashboard />
  }

  // Show manufacturer dashboard for manufacturer users
  if (user && user.role === 'manufacturer') {
    return <ManufacturerDashboard />
  }

  // Default dashboard for other roles
  return (
    <div className="dashboard-container">
      <aside className="dashboard-sidebar">
        <div className="dashboard-sidebar-header">
          <div className="medical-icon">+</div>
          <span style={{ fontWeight: 600, fontSize: '1.125rem', marginLeft: '0.5rem' }}>GenZipher</span>
        </div>
        <nav className="dashboard-sidebar-nav">
          <div className="dashboard-nav-item active">
            <div className="auth-nav-icon">📊</div>
            <span>Dashboard</span>
          </div>
        </nav>
      </aside>

      <main className="dashboard-main">
        <div className="dashboard-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>GenZipher Healthcare</h2>
              <p style={{ margin: '0.25rem 0 0 0', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                Session: <span>{user?.username || '—'} ({user?.role || '—'})</span>
              </p>
            </div>
            <div className="dashboard-header-actions">
              <button onClick={async () => { await logout(); navigate('/login') }} className="btn btn-sm btn-danger">Logout</button>
            </div>
          </div>
        </div>

        <div className="healthcare-card" style={{ marginTop: '2rem' }}>
          <h3>Welcome, {user?.username}!</h3>
          <p>Role: {user?.role}</p>
          <p style={{ color: 'var(--healthcare-text-muted)', marginTop: '1rem' }}>
            Dashboard functionality will be implemented here based on your role.
          </p>
        </div>
      </main>
    </div>
  )
}
