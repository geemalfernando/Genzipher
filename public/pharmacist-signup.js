function normalizeApiBase(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
}

function computeApiBase() {
  const host = window.location.hostname;
  const isFirebaseHost = host.endsWith(".web.app") || host.endsWith(".firebaseapp.com");
  const isVercelHost = host.endsWith(".vercel.app");

  const explicit = normalizeApiBase(typeof window.GZ_API_BASE === "string" ? window.GZ_API_BASE : "");
  if (explicit) return explicit === "https://genzipher.vercel.app" ? "https://genzipher.vercel.app/api" : explicit;

  const stored = normalizeApiBase(localStorage.getItem("gz_api_base") || "");
  if (stored) return stored === "https://genzipher.vercel.app" ? "https://genzipher.vercel.app/api" : stored;

  if (isFirebaseHost) return "https://genzipher.vercel.app/api";
  if (isVercelHost) return `${window.location.origin}/api`;
  return "";
}

const API_BASE = computeApiBase();

function $(id) {
  return document.getElementById(id);
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function toast(msg, type = "info") {
  const el = $("ps_toast");
  el.hidden = false;
  el.className = `flash flash-${type}`;
  el.textContent = msg;
  setTimeout(() => {
    el.hidden = true;
    el.textContent = "";
  }, 3500);
}

function getDeviceId() {
  let deviceId = localStorage.getItem("gz_device_id");
  if (!deviceId) {
    deviceId = `web_${crypto.randomUUID().replaceAll("-", "")}`;
    localStorage.setItem("gz_device_id", deviceId);
  }
  return deviceId;
}

async function api(path, { method = "GET", body } = {}) {
  const normalizedPath = typeof path === "string" && path.startsWith("/") ? path : `/${String(path || "")}`;
  const res = await fetch(`${API_BASE}${normalizedPath}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      "x-gz-device-id": getDeviceId(),
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

async function onSubmit(e) {
  e.preventDefault();
  try {
    const body = {
      username: $("ps_username").value.trim(),
      email: $("ps_email").value.trim(),
      password: $("ps_password").value,
      mfaCode: $("ps_mfa").value.trim(),
      deviceId: getDeviceId(),
    };
    const out = await api("/pharmacist/signup", { method: "POST", body });
    $("ps_out").value = pretty(out);
    localStorage.setItem("gz_token", out.token);
    toast("Account created. Redirecting…", "success");
    setTimeout(() => {
      window.location.href = "/";
    }, 800);
  } catch (err) {
    $("ps_out").value = pretty({ ok: false, error: err.message });
    toast(err.message, "error");
  }
}

$("ps_form").addEventListener("submit", onSubmit);
