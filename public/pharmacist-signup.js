const API_BASE = window.GZ_API_BASE || "";

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
  const res = await fetch(`${API_BASE}${path}`, {
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

