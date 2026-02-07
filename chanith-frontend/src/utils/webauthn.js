export function base64UrlToUint8Array(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('internal_error')
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padLen = b64.length % 4 === 0 ? 0 : 4 - (b64.length % 4)
  const padded = b64 + (padLen ? '='.repeat(padLen) : '')
  const raw = atob(padded)
  const bytes = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i)
  return bytes
}

export function arrayBufferToBytes(value) {
  return Array.from(new Uint8Array(value))
}

