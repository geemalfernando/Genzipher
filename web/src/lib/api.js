export function computeApiBase() {
  const explicit = typeof window.GZ_API_BASE === "string" ? window.GZ_API_BASE.trim() : "";
  const envBase = (import.meta.env.VITE_API_BASE || "").trim();

  const normalize = (v) => {
    if (!v) return "";
    return v.endsWith("/") ? v.slice(0, -1) : v;
  };

  // Prefer Vite env var, then window override.
  const base = normalize(envBase || explicit);
  if (base) return base;

  // Firebase Hosting -> Vercel backend default.
  const host = window.location.hostname;
  const isFirebaseHost = host.endsWith(".web.app") || host.endsWith(".firebaseapp.com");
  if (isFirebaseHost) return "https://genzipher.vercel.app/api";

  // If hosted on Vercel, use same-origin /api.
  const isVercelHost = host.endsWith(".vercel.app");
  if (isVercelHost) return `${window.location.origin}/api`;

  return "";
}

export function getToken() {
  return localStorage.getItem("gz_token") || localStorage.getItem("auth_token") || "";
}

export function setToken(token) {
  if (!token) {
    localStorage.removeItem("gz_token");
    localStorage.removeItem("auth_token");
    localStorage.removeItem("gz_csrf");
    return;
  }
  localStorage.setItem("gz_token", token);
  localStorage.setItem("auth_token", token);
}

export function getDeviceId() {
  let deviceId = localStorage.getItem("gz_device_id");
  if (!deviceId) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    deviceId = `web_${hex}`;
    localStorage.setItem("gz_device_id", deviceId);
  }
  return deviceId;
}

function getCsrfToken() {
  return (localStorage.getItem("gz_csrf") || "").trim();
}

function setCsrfToken(token) {
  if (!token) localStorage.removeItem("gz_csrf");
  else localStorage.setItem("gz_csrf", String(token));
}

async function ensureCsrfToken({ base, token, deviceId }) {
  if (!token) return;
  if (getCsrfToken()) return;
  try {
    const res = await fetch(`${base}/auth/csrf`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${token}`,
        "x-gz-device-id": deviceId,
      },
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data?.csrfToken) setCsrfToken(data.csrfToken);
  } catch {
    // ignore (backend may have CSRF disabled)
  }
}

export async function api(path, { method = "GET", token, body, headers } = {}) {
  const base = computeApiBase();
  const normalizedPath = typeof path === "string" && path.startsWith("/") ? path : `/${String(path || "")}`;
  const url = `${base}${normalizedPath}`;

  const authToken = (token || getToken() || "").trim();
  const deviceId = getDeviceId();
  const needsCsrf = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  if (needsCsrf && authToken) {
    await ensureCsrfToken({ base, token: authToken, deviceId });
  }

  const res = await fetch(url, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(authToken ? { authorization: `Bearer ${authToken}` } : {}),
      ...(deviceId ? { "x-gz-device-id": deviceId } : {}),
      ...(needsCsrf && getCsrfToken() ? { "x-gz-csrf": getCsrfToken() } : {}),
      ...(headers || {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error ? `${data.error}${data.message ? `: ${data.message}` : ""}` : `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}
