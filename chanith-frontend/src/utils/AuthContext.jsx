import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { api, getDeviceId, setToken as setTokenStorage } from './api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    return localStorage.getItem('gz_token') || null
  })

  const value = useMemo(() => {
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

    return { token, login, logout }
  }, [token])

  useEffect(() => {
    if (token) {
      localStorage.setItem('gz_token', token)
    } else {
      localStorage.removeItem('gz_token')
    }
  }, [token])

  // Global magic-link handler (new-device verification). Works from any page.
  useEffect(() => {
    const url = new URL(window.location.href)
    const mlt = url.searchParams.get('mlt')
    if (!mlt) return

    ;(async () => {
      try {
        const out = await api('/auth/magic-link/consume', {
          method: 'POST',
          body: { token: mlt, deviceId: getDeviceId() },
        })
        url.searchParams.delete('mlt')
        window.history.replaceState({}, '', url.toString())
        setToken(out.token)
        setTokenStorage(out.token)
      } catch (err) {
        console.error('Magic link consume error:', err)
      }
    })()
  }, [])

  return (
    <AuthContext.Provider value={value}>
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
