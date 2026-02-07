function normalizeApiBase(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
}

export function computeApiBase() {
  const envBase = normalizeApiBase(import.meta.env.VITE_API_BASE || "");
  const explicit = normalizeApiBase(typeof window.GZ_API_BASE === "string" ? window.GZ_API_BASE : "");
  const stored = normalizeApiBase(localStorage.getItem("gz_api_base") || "");

  const coerce = (base) => {
    const b = normalizeApiBase(base);
    if (!b) return "";
    // If someone provided the Vercel origin without /api, auto-fix for this app.
    if (b === "https://genzipher.vercel.app") return "https://genzipher.vercel.app/api";
    return b;
  };

  const base = coerce(envBase) || coerce(explicit) || coerce(stored);
  if (base) {
    localStorage.setItem("gz_api_base", base);
    return base;
  }

  const host = window.location.hostname;
  const isFirebaseHost = host.endsWith(".web.app") || host.endsWith(".firebaseapp.com");
  const isVercelHost = host.endsWith(".vercel.app");
  const isLocalhost =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "::1";

  if (isFirebaseHost) return "https://genzipher.vercel.app/api";
  if (isVercelHost) return `${window.location.origin}/api`;
  // Local dev default: use Vite dev server + proxy at `/api` to avoid CORS.
  if (isLocalhost) return `${window.location.origin}/api`;
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
      headers: { authorization: `Bearer ${token}`, "x-gz-device-id": deviceId },
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data?.csrfToken) setCsrfToken(data.csrfToken);
  } catch {
    // ignore (CSRF may be disabled)
  }
}

function getRememberMap() {
  const raw = localStorage.getItem("gz_remember_map");
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function setRememberMap(map) {
  localStorage.setItem("gz_remember_map", JSON.stringify(map));
}

export function getRememberTokenForIdentifier(identifier) {
  const key = String(identifier || "").trim().toLowerCase();
  const entry = getRememberMap()[key];
  return entry?.rememberToken || "";
}

export function setRememberTokenForIdentifier(identifier, rememberToken) {
  const key = String(identifier || "").trim().toLowerCase();
  const map = getRememberMap();
  map[key] = { rememberToken: String(rememberToken || "") };
  setRememberMap(map);
}

export async function api(endpoint, options = {}) {
  const base = computeApiBase();
  const normalized = typeof endpoint === "string" && endpoint.startsWith("/") ? endpoint : `/${String(endpoint || "")}`;
  const url = `${base}${normalized}`;

  const token = getToken();
  const deviceId = getDeviceId();
  const method = (options.method || "GET").toUpperCase();
  const needsCsrf = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  if (needsCsrf && token) await ensureCsrfToken({ base, token, deviceId });

  const headers = {
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(options.headers || {}),
    ...(token && !options.headers?.Authorization ? { Authorization: `Bearer ${token}` } : {}),
    ...(deviceId ? { "x-gz-device-id": deviceId } : {}),
    ...(needsCsrf && getCsrfToken() ? { "x-gz-csrf": getCsrfToken() } : {}),
  };

  const response = await fetch(url, {
    ...options,
    method,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json().catch(() => ({}))
    : { error: "non_json_response", message: (await response.text().catch(() => "")).slice(0, 200) };

  if (!response.ok) {
    // Auto-recover once if CSRF became invalid (common after backend redeploy).
    if (
      needsCsrf &&
      token &&
      !options.__retried &&
      response.status === 403 &&
      (data?.error === "csrf_invalid" || data?.error === "csrf_missing")
    ) {
      setCsrfToken(null);
      await ensureCsrfToken({ base, token, deviceId });
      return api(endpoint, { ...options, __retried: true });
    }

    const errorMessage = data?.message || data?.error || `Request failed with status ${response.status}`;
    const error = new Error(errorMessage);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

export function toast(message, type = "info") {
  const toastEl = document.createElement("div");
  toastEl.className = `flash flash-${type === "error" ? "error" : type === "success" ? "success" : "warning"}`;
  toastEl.textContent = message;
  toastEl.style.position = "fixed";
  toastEl.style.top = "1rem";
  toastEl.style.right = "1rem";
  toastEl.style.zIndex = "10000";
  toastEl.style.minWidth = "300px";
  document.body.appendChild(toastEl);

  setTimeout(() => {
    toastEl.remove();
  }, 5000);
}
