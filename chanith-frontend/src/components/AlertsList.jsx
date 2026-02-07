import { toast } from '../utils/api'

function severityMeta(severity) {
  const sev = String(severity || 'info').toLowerCase()
  if (sev === 'critical') return { sev, label: 'Critical', color: '#b00020', bg: '#b0002018', icon: '⛔' }
  if (sev === 'high') return { sev, label: 'High', color: '#e55353', bg: '#e5535314', icon: '⚠️' }
  if (sev === 'medium') return { sev, label: 'Medium', color: '#f5a623', bg: '#f5a62314', icon: '🟠' }
  if (sev === 'low') return { sev, label: 'Low', color: '#6c757d', bg: '#6c757d14', icon: '🟡' }
  return { sev: 'info', label: 'Info', color: '#3b82f6', bg: '#3b82f614', icon: 'ℹ️' }
}

function formatActor(actor) {
  const a = actor || {}
  const who = a.username || a.userId || a.identifier || '—'
  const role = a.role ? String(a.role) : ''
  return role ? `${who} (${role})` : who
}

export default function AlertsList({
  alerts,
  limit = 25,
  onInvestigate,
  showType = true,
  compact = false,
}) {
  const list = Array.isArray(alerts) ? alerts.slice(0, limit) : []
  if (list.length === 0) return <p className="empty-state" style={{ marginTop: '1rem' }}>No alerts</p>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: compact ? '0.5rem' : '0.75rem', marginTop: '1rem' }}>
      {list.map((a, idx) => {
        const meta = severityMeta(a?.severity)
        const ts = a?.ts ? new Date(a.ts).toLocaleString() : '—'
        const title = a?.title || a?.type || 'Alert'
        const actorText = formatActor(a?.actor)
        const type = a?.type ? String(a.type) : ''
        const details = a?.details ? a.details : null

        return (
          <div
            key={`${a?.ts || 'na'}_${idx}`}
            style={{
              border: '1px solid var(--healthcare-border)',
              borderLeft: `6px solid ${meta.color}`,
              borderRadius: '12px',
              padding: compact ? '0.75rem' : '1rem',
              background: meta.bg,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <div style={{ minWidth: 220, flex: 1 }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span aria-hidden="true">{meta.icon}</span>
                  <span style={{ fontWeight: 800 }}>{title}</span>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '0.15rem 0.5rem',
                      borderRadius: '999px',
                      background: `${meta.color}22`,
                      color: meta.color,
                      fontWeight: 800,
                      fontSize: '0.75rem',
                    }}
                  >
                    {meta.label.toUpperCase()}
                  </span>
                </div>
                <div style={{ marginTop: '0.35rem', color: 'var(--healthcare-text-muted)', fontSize: '0.875rem' }}>
                  {ts} • {actorText}
                  {showType && type ? (
                    <>
                      {' '}
                      • <span style={{ fontFamily: 'monospace' }}>{type}</span>
                    </>
                  ) : null}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                {typeof onInvestigate === 'function' ? (
                  <button className="btn-secondary btn-sm" type="button" onClick={() => onInvestigate(a)}>
                    Investigate
                  </button>
                ) : null}
                <button
                  className="btn-secondary btn-sm"
                  type="button"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(JSON.stringify(a, null, 2))
                      toast('Alert JSON copied', 'success')
                    } catch {
                      toast('Copy failed', 'error')
                    }
                  }}
                >
                  Copy JSON
                </button>
              </div>
            </div>

            {details ? (
              <details style={{ marginTop: '0.6rem' }}>
                <summary style={{ cursor: 'pointer', color: 'var(--healthcare-text-muted)' }}>Details</summary>
                <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  {JSON.stringify(details, null, 2)}
                </pre>
              </details>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}

