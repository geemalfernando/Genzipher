import { useEffect, useState } from 'react'
import { api } from '../utils/api'

export default function HealthCheck() {
  const [status, setStatus] = useState('checking')
  const [error, setError] = useState(null)

  useEffect(() => {
    checkHealth()
  }, [])

  const checkHealth = async () => {
    try {
      const data = await api('/health')
      if (data.ok) {
        setStatus('connected')
        setError(null)
      } else {
        setStatus('error')
        setError('Health check failed')
      }
    } catch (err) {
      setStatus('error')
      setError(err.message)
    }
  }

  if (status === 'checking') {
    return (
      <div style={{ padding: '1rem', background: '#fff3cd', borderRadius: '8px', marginBottom: '1rem' }}>
        <strong>Checking backend connection...</strong>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div style={{ padding: '1rem', background: '#f8d7da', borderRadius: '8px', marginBottom: '1rem', color: '#721c24' }}>
        <strong>⚠️ Backend Connection Error:</strong>
        <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>{error}</p>
        <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
          Make sure the backend server is running: <code>npm run dev</code>
        </p>
        <button onClick={checkHealth} style={{ marginTop: '0.5rem', padding: '0.5rem 1rem', cursor: 'pointer' }}>
          Retry Connection
        </button>
      </div>
    )
  }

  return (
    <div style={{ padding: '1rem', background: '#d1fae5', borderRadius: '8px', marginBottom: '1rem', color: '#065f46' }}>
      <strong>✅ Backend Connected</strong>
      <p style={{ marginTop: '0.25rem', fontSize: '0.875rem' }}>
        Server is running and ready to accept requests
      </p>
    </div>
  )
}

