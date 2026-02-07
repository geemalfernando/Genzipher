import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Landing from './pages/Landing'
import Login from './pages/Login'
import Signup from './pages/Signup'
import PharmacistSignup from './pages/PharmacistSignup'
import ForgotPassword from './pages/ForgotPassword'
import Dashboard from './pages/Dashboard'
import { AuthProvider, useAuth } from './utils/AuthContext'

function ProtectedRoute({ children }) {
  const { token } = useAuth()
  return token ? children : <Navigate to="/login" replace />
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/pharmacist/signup" element={<PharmacistSignup />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

function App() {
  return (
    <AuthProvider>
      <Router future={{ v7_startTransition: true }}>
        <AppRoutes />
      </Router>
    </AuthProvider>
  )
}

export default App
