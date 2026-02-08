import { useState } from 'react'
import { api, toast } from '../utils/api'

export default function TotpSetupCard({ title = 'Authenticator MFA (TOTP)', onEnabled }) {
  const [loading, setLoading] = useState(false)
  const [setup, setSetup] = useState(null) // { secretB32, otpauthUrl, setupToken }
  const [code, setCode] = useState('')

  const start = async () => {
    try {
      setLoading(true)
      const out = await api('/mfa/totp/start', { method: 'POST' })
      setSetup(out)
      setCode('')
      toast('TOTP secret generated. Add it to your authenticator app.', 'success')
    } catch (err) {
      toast(err.message || 'Failed to start TOTP setup', 'error')
    } finally {
      setLoading(false)
    }
  }

  const confirm = async () => {
    if (!setup?.setupToken) return toast('Start setup first', 'warning')
    if (!/^[0-9]{6}$/.test(String(code || '').trim())) return toast('Enter a valid 6-digit code', 'error')
    try {
      setLoading(true)
      await api('/mfa/totp/confirm', { method: 'POST', body: { setupToken: setup.setupToken, code } })
      toast('Authenticator MFA enabled', 'success')
      setSetup(null)
      setCode('')
      if (typeof onEnabled === 'function') onEnabled()
    } catch (err) {
      toast(err.message || 'Failed to enable TOTP', 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="healthcare-card">
      <h2 style={{ marginTop: 0 }}>{title}</h2>
      <p style={{ color: 'var(--healthcare-text-muted)', marginTop: '0.25rem' }}>
        This MFA is unique per user and does not use email. Use Google Authenticator / Microsoft Authenticator.
      </p>

      {!setup ? (
        <button type="button" className="btn-primary" onClick={start} disabled={loading}>
          {loading ? 'Generating…' : 'Generate setup'}
        </button>
      ) : (
        <div style={{ marginTop: '1rem' }}>
          <div className="auth-alert auth-alert-info" style={{ marginBottom: '1rem' }}>
            <div className="alert-content">
              <strong>Step 1</strong>
              <p style={{ margin: 0 }}>
                Add this secret to your authenticator app, then enter the 6‑digit code to confirm.
              </p>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Secret (Base32)</label>
            <input className="form-input" value={setup.secretB32 || ''} readOnly style={{ fontFamily: 'monospace' }} />
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn-secondary btn-sm"
              onClick={async () => {
                await navigator.clipboard.writeText(String(setup.secretB32 || ''))
                toast('Secret copied', 'success')
              }}
            >
              Copy secret
            </button>
            <button
              type="button"
              className="btn-secondary btn-sm"
              onClick={async () => {
                await navigator.clipboard.writeText(String(setup.otpauthUrl || ''))
                toast('otpauth URL copied', 'success')
              }}
            >
              Copy otpauth URL
            </button>
          </div>

          <div className="form-group" style={{ marginTop: '1rem' }}>
            <label className="form-label">6‑digit code</label>
            <input
              className="form-input"
              value={code}
              onChange={(e) => setCode(String(e.target.value || '').replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              inputMode="numeric"
              maxLength={6}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button type="button" className="btn-primary" onClick={confirm} disabled={loading}>
              {loading ? 'Enabling…' : 'Enable MFA'}
            </button>
            <button type="button" className="btn-secondary" onClick={() => setSetup(null)} disabled={loading}>
              Cancel
            </button>
          </div>

          <p style={{ marginTop: '0.75rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
            If you lose access to your authenticator and also can’t reset your password, contact admin for MFA reset.
          </p>
        </div>
      )}
    </div>
  )
}

