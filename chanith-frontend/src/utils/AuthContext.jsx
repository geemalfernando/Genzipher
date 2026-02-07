import { createContext, useContext, useState, useEffect } from 'react'
import { api, setToken as setTokenStorage } from './api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    return localStorage.getItem('gz_token') || null
  })

  useEffect(() => {
    if (token) {
      localStorage.setItem('gz_token', token)
    } else {
      localStorage.removeItem('gz_token')
    }
  }, [token])

  const login = (newToken) => {
    setToken(newToken)
    setTokenStorage(newToken)
  }

  const logout = async () => {
    if (token) {
      try {
        await api('/auth/logout', { method: 'POST' })
      } catch (err) {
        console.error('Logout error:', err)
      }
    }
    setToken(null)
    setTokenStorage(null)
  }

  return (
    <AuthContext.Provider value={{ token, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}
