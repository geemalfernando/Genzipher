function computeApiBase() {
  const explicit = typeof window.GZ_API_BASE === "string" ? window.GZ_API_BASE.trim() : "";
  const stored = (localStorage.getItem("gz_api_base") || "").trim();
  const isFirebaseHost =
    window.location.hostname.endsWith(".web.app") || window.location.hostname.endsWith(".firebaseapp.com");
  // Prefer the explicit Vercel Functions base path to avoid relying on Vercel rewrites for non-GET methods (e.g. CORS preflight OPTIONS).
  const auto = isFirebaseHost ? "https://genzipher.vercel.app/api" : "";
  const base = explicit || stored || auto || "";
  window.GZ_API_BASE = base;
  return base;
}

const API_BASE = computeApiBase();

function $(id) {
  return document.getElementById(id);
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object" && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function base64urlFromBytes(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  const b64 = btoa(binary);
  return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function pemFromSpki(spkiBytes) {
  let b64 = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < spkiBytes.length; i += chunkSize) {
    b64 += String.fromCharCode(...spkiBytes.subarray(i, i + chunkSize));
  }
  b64 = btoa(b64);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

function openIdb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("genzipher_mvp", 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys");
    };
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
  });
}

async function idbGet(storeName, key) {
  const db = await openIdb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const store = tx.objectStore(storeName);
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(storeName, key, value) {
  const db = await openIdb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const req = store.put(value, key);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}

async function getOrCreateP256KeyPair() {
  const existing = await idbGet("keys", "p256");
  if (existing?.privateKey && existing?.publicKey) return existing;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  await idbPut("keys", "p256", pair);
  return pair;
}

async function exportSpkiPem(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return pemFromSpki(new Uint8Array(spki));
}

async function signEs256(privateKey, obj) {
  const msg = new TextEncoder().encode(stableStringify(obj));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, msg);
  return base64urlFromBytes(new Uint8Array(sig));
}

function setStatus(ok, label) {
  const dot = $("apiDot");
  const text = $("apiStatusText");
  dot.classList.remove("ok", "bad");
  dot.classList.add(ok ? "ok" : "bad");
  text.textContent = label;
}

function toast(message, variant = "info") {
  const el = $("toast");
  el.className = `flash flash-${variant}`;
  el.textContent = message;
  el.hidden = false;
  window.clearTimeout(window.__toastTimer);
  window.__toastTimer = window.setTimeout(() => (el.hidden = true), 4000);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatActor(actor) {
  if (!actor) return "—";
  const username = actor.username || actor.identifier || actor.patientId || actor.userId;
  const role = actor.role ? ` (${actor.role})` : "";
  return `${username || "—"}${role}`;
}

function shortDetails(details) {
  if (!details) return "—";
  if (typeof details === "string") return details.slice(0, 160);
  try {
    const s = JSON.stringify(details);
    return s.length > 200 ? `${s.slice(0, 200)}…` : s;
  } catch {
    return "—";
  }
}

function renderAuditReadable(targetEl, payload) {
  const entries = payload?.entries || [];
  const sanity = payload?.chainSanity || chainSanity(entries);
  const counts = payload?.countsByAction || {};

  const countsRows = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([action, n]) => `<span class="Label Label--secondary mr-1 mb-1">${escapeHtml(action)}: ${n}</span>`)
    .join("");

  const rows = entries
    .slice(0, 200)
    .map((e) => {
      const ts = e.ts ? new Date(e.ts).toLocaleString() : "—";
      return `<tr>
        <td class="text-small color-fg-muted">${escapeHtml(ts)}</td>
        <td class="text-small"><span class="Label Label--accent">${escapeHtml(e.action || "—")}</span></td>
        <td class="text-small">${escapeHtml(formatActor(e.actor))}</td>
        <td class="text-small color-fg-muted">${escapeHtml(shortDetails(e.details))}</td>
      </tr>`;
    })
    .join("");

  targetEl.innerHTML = `
    <div class="d-flex flex-items-center flex-wrap gap-2">
      <span class="Label ${sanity.ok ? "Label--success" : "Label--danger"}">Chain: ${sanity.ok ? "OK" : "Mismatch"}</span>
      <span class="Label Label--secondary">Entries: ${entries.length}</span>
    </div>
    <div class="mt-2">${countsRows || '<span class="color-fg-muted text-small">No entries yet.</span>'}</div>
    <div class="mt-2 overflow-x-auto">
      <table class="table-list width-full">
        <thead>
          <tr>
            <th class="text-small">Time</th>
            <th class="text-small">Action</th>
            <th class="text-small">Actor</th>
            <th class="text-small">Details</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function labelForStatus(status) {
  const s = String(status || "").toUpperCase();
  if (s === "ACTIVE" || s === "VERIFIED") return { text: s, cls: "Label--success" };
  if (s === "PENDING") return { text: s, cls: "Label--attention" };
  if (s === "QUARANTINED") return { text: s, cls: "Label--danger" };
  return { text: s || "—", cls: "Label--secondary" };
}

function renderPatientProfileReadable(payload) {
  const profile = payload?.profile || {};
  const user = payload?.user || {};
  const token = payload?.patientToken || "—";

  const statusInfo = labelForStatus(profile.status);
  const badge = $("patientStatusBadge");
  badge.textContent = statusInfo.text;
  badge.className = `Label ${statusInfo.cls}`;

  const createdFromDeviceId = user.createdFromDeviceId || "—";
  const lastLoginDeviceId = user.lastLoginDeviceId || "—";
  const lastLoginAt = user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : "—";

  const top3 = Array.isArray(profile.trustExplainTop3) ? profile.trustExplainTop3 : [];
  const chips = top3
    .slice(0, 3)
    .map((x) => `<span class="Label Label--secondary mr-1 mb-1">${escapeHtml(x)}</span>`)
    .join("");

  const html = `
    <div class="d-flex flex-wrap gap-2">
      <span class="Label ${statusInfo.cls}">Status: ${escapeHtml(statusInfo.text)}</span>
      <span class="Label Label--accent">DID: <span class="gz-mono">${escapeHtml(profile.did || "—")}</span></span>
      <span class="Label Label--secondary">Trust score: ${escapeHtml(profile.trustScore ?? "—")}</span>
      <span class="Label Label--secondary">User: <span class="gz-mono">${escapeHtml(user.username || "—")}</span></span>
      <span class="Label Label--secondary">Email: <span class="gz-mono">${escapeHtml(user.email || "—")}</span></span>
    </div>
    <div class="mt-2 d-flex flex-wrap gap-2">
      <span class="Label Label--secondary">Created device: <span class="gz-mono">${escapeHtml(createdFromDeviceId)}</span></span>
      <span class="Label Label--secondary">Last login device: <span class="gz-mono">${escapeHtml(lastLoginDeviceId)}</span></span>
      <span class="Label Label--secondary">Last login at: ${escapeHtml(lastLoginAt)}</span>
    </div>
    <div class="mt-2">
      <div class="text-small color-fg-muted">Patient token</div>
      <div class="gz-mono">${escapeHtml(token)}</div>
    </div>
    <div class="mt-2">
      <div class="text-small color-fg-muted">Trust score explainability (top factors)</div>
      <div class="mt-1">${chips || '<span class="color-fg-muted text-small">—</span>'}</div>
    </div>
    <div class="mt-2 d-flex flex-wrap gap-2">
      <span class="Label Label--secondary">MFA: ${user.mfaEnabled ? "ON" : "OFF"} (${escapeHtml(user.mfaMethod || "NONE")})</span>
      <span class="Label Label--secondary">Created: ${escapeHtml(profile.createdAt ? new Date(profile.createdAt).toLocaleString() : "—")}</span>
      <span class="Label Label--secondary">Updated: ${escapeHtml(profile.updatedAt ? new Date(profile.updatedAt).toLocaleString() : "—")}</span>
    </div>
  `;

  $("patientProfileReadable").innerHTML = html;
}

function renderLoginDevicesReadable(payload) {
  const user = payload?.user || {};
  const devices = Array.isArray(payload?.devices) ? payload.devices : [];
  const createdFrom = user.createdFromDeviceId || null;
  const lastLoginDeviceId = user.lastLoginDeviceId || null;

  const summary = `
    <div class="d-flex flex-wrap gap-2">
      <span class="Label Label--secondary">Account created device: <span class="gz-mono">${escapeHtml(createdFrom || "—")}</span></span>
      <span class="Label Label--secondary">Last used device: <span class="gz-mono">${escapeHtml(lastLoginDeviceId || "—")}</span></span>
      <span class="Label Label--secondary">Last login at: ${escapeHtml(user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : "—")}</span>
      <span class="Label Label--secondary">Devices seen: ${devices.length}</span>
    </div>
  `;

  const rows = devices
    .slice(0, 50)
    .map((d) => {
      const isCreated = createdFrom && d.deviceId === createdFrom;
      const isLast = lastLoginDeviceId && d.deviceId === lastLoginDeviceId;
      const flags = [
        isLast ? `<span class="Label Label--success mr-1">LAST</span>` : "",
        isCreated ? `<span class="Label Label--secondary mr-1">CREATED</span>` : "",
        d.verifiedAt ? `<span class="Label Label--success mr-1">VERIFIED</span>` : `<span class="Label Label--attention mr-1">UNVERIFIED</span>`,
        d.blockedAt ? `<span class="Label Label--danger mr-1">BLOCKED</span>` : "",
      ]
        .filter(Boolean)
        .join("");

      const ip = d.lastIp || d.firstIp || "—";
      const ua = d.lastUserAgent ? String(d.lastUserAgent) : "—";
      const uaShort = ua.length > 60 ? `${ua.slice(0, 60)}…` : ua;

      return `<tr>
        <td class="text-small">${flags || "—"}</td>
        <td class="text-small"><span class="gz-mono">${escapeHtml(d.deviceId || "—")}</span></td>
        <td class="text-small color-fg-muted">${escapeHtml(d.firstSeenAt ? new Date(d.firstSeenAt).toLocaleString() : "—")}</td>
        <td class="text-small color-fg-muted">${escapeHtml(d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : "—")}</td>
        <td class="text-small color-fg-muted"><span class="gz-mono">${escapeHtml(ip)}</span></td>
        <td class="text-small color-fg-muted" title="${escapeHtml(ua)}">${escapeHtml(uaShort)}</td>
      </tr>`;
    })
    .join("");

  $("loginDevicesReadable").innerHTML = `
    ${summary}
    <div class="mt-2 overflow-x-auto">
      <table class="table-list width-full">
        <thead>
          <tr>
            <th class="text-small">Flags</th>
            <th class="text-small">Device ID</th>
            <th class="text-small">First seen</th>
            <th class="text-small">Last seen</th>
            <th class="text-small">IP</th>
            <th class="text-small">User-Agent</th>
          </tr>
        </thead>
        <tbody>
          ${rows || `<tr><td colspan="6" class="text-small color-fg-muted">No devices recorded yet.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function getToken() {
  return localStorage.getItem("gz_token");
}

function setToken(token) {
  if (!token) localStorage.removeItem("gz_token");
  else localStorage.setItem("gz_token", token);
  updateAuthUi();
}

function getDeviceId() {
  let deviceId = localStorage.getItem("gz_device_id");
  if (!deviceId) {
    deviceId = `web_${cryptoRandomId()}`;
    localStorage.setItem("gz_device_id", deviceId);
  }
  return deviceId;
}

function cryptoRandomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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

function getRememberTokenForIdentifier(identifier) {
  const map = getRememberMap();
  const key = (identifier || "").trim().toLowerCase();
  const entry = map[key];
  return entry?.rememberToken || null;
}

function rememberTokenForIdentifier(identifier, rememberToken) {
  const map = getRememberMap();
  const key = (identifier || "").trim().toLowerCase();
  map[key] = { rememberToken };
  setRememberMap(map);
}

function forgetRememberTokenForIdentifier(identifier) {
  const map = getRememberMap();
  const key = (identifier || "").trim().toLowerCase();
  delete map[key];
  setRememberMap(map);
}

function setPendingOtpState(state) {
  if (!state) localStorage.removeItem("gz_pending_otp");
  else localStorage.setItem("gz_pending_otp", JSON.stringify(state));
}

function getPendingOtpState() {
  const raw = localStorage.getItem("gz_pending_otp");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function api(path, { method = "GET", body } = {}) {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      "x-gz-device-id": getDeviceId(),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
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

function showRole(role) {
  const roles = ["doctor", "manufacturer", "pharmacy", "admin", "patient"];
  for (const r of roles) {
    const section = $(`role_${r}`);
    if (section) section.hidden = r !== role;
  }
}

function setAccessTab(tab) {
  const loginPane = $("loginPane");
  const registerPane = $("registerPane");
  const tabLogin = $("tabLogin");
  const tabRegister = $("tabRegister");

  const isLogin = tab === "login";
  loginPane.hidden = !isLogin;
  registerPane.hidden = isLogin;

  tabLogin.classList.toggle("btn-primary", isLogin);
  tabRegister.classList.toggle("btn-primary", !isLogin);
}

async function updateAuthUi() {
  const token = getToken();
  $("logoutBtn").hidden = !token;
  $("loginBox").hidden = Boolean(token);
  $("appBox").hidden = !token;

  if (!token) {
    $("whoami").textContent = "Not logged in";
    showRole("doctor");
    setAccessTab("login");

    const pending = getPendingOtpState();
    $("otpBox").hidden = !pending;
    if (pending) {
      $("otp_expires").textContent = pending.expiresAt || "—";
      $("otp_sentTo").textContent = pending.sentTo || "—";
    }
    return;
  }

  try {
    const whoami = await api("/demo/whoami");
    const auth = whoami.auth;
    $("whoami").textContent = `${auth.username} (${auth.role})`;
    $("currentRole").textContent = auth.role;
    showRole(auth.role);

    const users = await api("/demo/users");
    const patientSelect = $("rx_patientUserId");
    patientSelect.innerHTML = "";
    for (const user of users.users.filter((u) => u.role === "patient")) {
      const opt = document.createElement("option");
      opt.value = user.id;
      opt.textContent = `${user.username} (${user.id})`;
      patientSelect.appendChild(opt);
    }

    if (auth.role === "admin") {
      const sel = $("adminUserSelect");
      sel.innerHTML = "";
      for (const u of users.users) {
        const opt = document.createElement("option");
        opt.value = `${u.id}|${u.username}`;
        opt.textContent = `${u.username} (${u.role})`;
        sel.appendChild(opt);
      }

      // Prime admin dashboard lists
      await onLoadPendingPatients();
    }

    if (auth.role === "patient") {
      await refreshPatientProfile();
      await loadTrustedDevices();
      await autoBindDevice();
    }

    if (auth.role === "pharmacy") {
      await pharmacyLoadBiometricStatus();
    }
  } catch (err) {
    setToken(null);
    toast(`Session expired: ${err.message}`, "error");
  }
}

async function checkHealth() {
  try {
    await api("/health");
    setStatus(true, `API reachable (${API_BASE || "same-origin"})`);
  } catch {
    setStatus(false, `API not reachable (${API_BASE || "same-origin"})`);
  }
}

function safeParseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

async function onLogin(e) {
  e.preventDefault();
  try {
    const identifier = $("login_identifier").value.trim();
    const password = $("login_password").value;
    const mfaCode = $("login_mfa").value.trim() || undefined;
    const deviceId = getDeviceId();
    const rememberToken = getRememberTokenForIdentifier(identifier) || undefined;
    const out = await api("/auth/login", { method: "POST", body: { identifier, password, mfaCode, deviceId, rememberToken } });
    if (out.mfaRequired && out.method === "EMAIL_LINK" && out.reason === "NEW_DEVICE") {
      toast("New device detected. Check your email and click the verification link.", "warning");
      return;
    }
    if (out.mfaRequired && out.method === "EMAIL_OTP") {
      setPendingOtpState({
        otpRequestId: out.otpRequestId,
        expiresAt: out.expiresAt,
        sentTo: out.sentTo,
        delivery: out.delivery,
        identifier,
        userId: out.userId,
        reason: out.reason || null,
      });
      $("otpBox").hidden = false;
      $("otp_expires").textContent = out.expiresAt || "—";
      $("otp_sentTo").textContent = out.sentTo || "—";
      toast(out.reason === "NEW_DEVICE" ? "New device detected. OTP sent." : "OTP required. Check server logs for code (MVP).", "warning");
      return;
    }
    setPendingOtpState(null);
    setToken(out.token);
    toast("Logged in", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

function onLogout() {
  (async () => {
    try {
      await api("/auth/logout", { method: "POST", body: {} });
    } catch {
      // ignore
    }
    setToken(null);
    setPendingOtpState(null);
    toast("Logged out", "success");
  })();
}

function b64uToBuf(b64u) {
  const b64 = String(b64u).replaceAll("-", "+").replaceAll("_", "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  const b64 = btoa(bin);
  return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function pharmacyLoadBiometricStatus() {
  const box = $("pharmacyBioBox");
  const out = $("pharmacyBioOut");
  try {
    const status = await api("/pharmacy/biometric-status");
    const enrolled = await api("/biometric/status");
    out.value = pretty({ status, enrolled });

    const msg = $("pharmacyBioMsg");
    const enrollBtn = $("pharmacyEnrollBtn");
    const verifyBtn = $("pharmacyVerifyBtn");

    if (status.biometricVerified) {
      box.hidden = true;
      return;
    }

    box.hidden = false;
    if (!enrolled.enrolled) {
      msg.textContent = "No biometric enrolled yet. Enroll once to continue.";
      enrollBtn.hidden = false;
      verifyBtn.hidden = true;
    } else {
      msg.textContent = "Biometric verification required for this session. Please verify.";
      enrollBtn.hidden = true;
      verifyBtn.hidden = false;
    }
  } catch (err) {
    box.hidden = false;
    out.value = pretty({ ok: false, error: err.message });
    $("pharmacyBioMsg").textContent = `Biometric status error: ${err.message}`;
  }
}

async function pharmacyEnrollBiometric() {
  try {
    if (!window.PublicKeyCredential) throw new Error("WebAuthn not supported in this browser");
    const start = await api("/biometric/enroll/start", { method: "POST", body: {} });
    const pk = start.publicKey;
    const options = {
      publicKey: {
        ...pk,
        challenge: b64uToBuf(pk.challenge),
        user: { ...pk.user, id: b64uToBuf(pk.user.id) },
        excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
      },
    };
    const cred = await navigator.credentials.create(options);
    const json = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
      },
    };
    const done = await api("/biometric/enroll/complete", { method: "POST", body: { credential: json } });
    $("pharmacyBioOut").value = pretty(done);
    toast("Biometric enrolled", "success");
    await pharmacyLoadBiometricStatus();
  } catch (err) {
    $("pharmacyBioOut").value = pretty({ ok: false, error: err.message });
    toast(err.message, "error");
  }
}

async function pharmacyVerifyBiometric() {
  try {
    if (!window.PublicKeyCredential) throw new Error("WebAuthn not supported in this browser");
    const start = await api("/biometric/verify/start", { method: "POST", body: {} });
    const pk = start.publicKey;
    const options = {
      publicKey: {
        ...pk,
        challenge: b64uToBuf(pk.challenge),
        allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
      },
    };
    const assertion = await navigator.credentials.get(options);
    const json = {
      id: assertion.id,
      rawId: bufToB64u(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
        authenticatorData: bufToB64u(assertion.response.authenticatorData),
        signature: bufToB64u(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
      },
    };
    const done = await api("/biometric/verify/complete", { method: "POST", body: { credential: json } });
    $("pharmacyBioOut").value = pretty(done);
    toast("Biometric verified", "success");
    await pharmacyLoadBiometricStatus();
  } catch (err) {
    $("pharmacyBioOut").value = pretty({ ok: false, error: err.message });
    toast(err.message, "error");
  }
}

async function onVerifyOtp(e) {
  e.preventDefault();
  const pending = getPendingOtpState();
  if (!pending?.otpRequestId) return toast("No pending OTP request.", "error");
  try {
    const otp = $("otp_code").value.trim();
    const rememberDevice = Boolean($("otp_remember").checked);
    const deviceId = getDeviceId();
    const out = await api("/auth/verify-otp", {
      method: "POST",
      body: { otpRequestId: pending.otpRequestId, otp, rememberDevice, deviceId },
    });
    if (out.rememberToken && pending.identifier) {
      rememberTokenForIdentifier(pending.identifier, out.rememberToken);
    }
    setPendingOtpState(null);
    $("otpBox").hidden = true;
    setToken(out.token);
    toast("OTP verified. Logged in.", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onResendOtp() {
  const pending = getPendingOtpState();
  if (!pending?.otpRequestId) return toast("No pending OTP request.", "error");
  try {
    const out = await api("/auth/resend-otp", { method: "POST", body: { otpRequestId: pending.otpRequestId } });
    toast(`OTP resent (${out.delivery}). Check server logs.`, "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onPreRegister(e) {
  e.preventDefault();
  try {
    const body = {
      username: $("pr_username").value.trim(),
      email: $("pr_email").value.trim() || undefined,
      password: $("pr_password").value,
      deviceId: getDeviceId(),
    };
    const out = await api("/patients/pre-register", { method: "POST", body });
    $("pr_out").value = pretty(out);
    if (out.patientId) {
      $("vc_patientId").value = out.patientId;
      $("vc_username").value = body.username;
    }
    if (out.status === "PENDING" && out.verification?.required) {
      const d = out.verification.delivery || "console";
      toast(`Pre-registered: PENDING. Verification code sent (${d}).`, "warning");
    } else {
      toast(`Pre-registered: ${out.status} (score ${out.trustScore})`, out.status === "PENDING" ? "warning" : "success");
    }
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onVerifyClinicCode(e) {
  e.preventDefault();
  try {
    const body = {
      username: $("vc_username").value.trim() || undefined,
      patientId: $("vc_patientId").value.trim() || undefined,
      code: $("vc_code").value.trim().toUpperCase(),
    };
    const out = await api("/patients/verify-clinic-code", { method: "POST", body });
    $("vc_out").value = pretty(out);
    toast("Patient verified", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onCreateRx(e) {
  e.preventDefault();
  try {
    const body = {
      patientUserId: $("rx_patientUserId").value,
      medicineId: $("rx_medicineId").value.trim(),
      dosage: $("rx_dosage").value.trim(),
      durationDays: Number($("rx_durationDays").value),
    };
    const rx = await api("/prescriptions", { method: "POST", body });
    $("rx_out").value = pretty(rx);
    toast("Prescription signed", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onVerifyRx() {
  const parsed = safeParseJson($("rx_out").value);
  if (!parsed.ok) return toast(`Bad Rx JSON: ${parsed.error}`, "error");
  try {
    const result = await api("/prescriptions/verify", { method: "POST", body: { prescription: parsed.value } });
    $("rx_verify_out").value = pretty(result);
    toast(result.ok ? "Rx verification OK" : "Rx verification FAILED", result.ok ? "success" : "error");
  } catch (err) {
    toast(err.message, "error");
  }
}

function onTamperRx() {
  const parsed = safeParseJson($("rx_out").value);
  if (!parsed.ok) return toast(`Bad Rx JSON: ${parsed.error}`, "error");
  parsed.value.dosage = `${parsed.value.dosage} (tampered)`;
  $("rx_out").value = pretty(parsed.value);
  toast("Tampered dosage field (signature should fail)", "warning");
}

async function onCreateBatch(e) {
  e.preventDefault();
  try {
    const body = {
      batchId: $("batch_batchId").value.trim(),
      lot: $("batch_lot").value.trim(),
      expiry: $("batch_expiry").value,
      certificateHash: $("batch_certHash").value.trim(),
    };
    const batch = await api("/batches", { method: "POST", body });
    $("batch_out").value = pretty(batch);
    toast("Batch certificate signed", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onVerifyBatch() {
  const parsed = safeParseJson($("batch_out").value);
  if (!parsed.ok) return toast(`Bad batch JSON: ${parsed.error}`, "error");
  try {
    const result = await api("/batches/verify", { method: "POST", body: { batch: parsed.value } });
    $("batch_verify_out").value = pretty(result);
    toast(result.ok ? "Batch verification OK" : "Batch verification FAILED", result.ok ? "success" : "error");
  } catch (err) {
    toast(err.message, "error");
  }
}

function onTamperBatch() {
  const parsed = safeParseJson($("batch_out").value);
  if (!parsed.ok) return toast(`Bad batch JSON: ${parsed.error}`, "error");
  parsed.value.lot = `${parsed.value.lot}-tampered`;
  $("batch_out").value = pretty(parsed.value);
  toast("Tampered lot field (signature should fail)", "warning");
}

async function onDispense(e) {
  e.preventDefault();
  const rxParsed = safeParseJson($("dispense_rx").value);
  if (!rxParsed.ok) return toast(`Bad Rx JSON: ${rxParsed.error}`, "error");
  const batchParsed = safeParseJson($("dispense_batch").value);
  if (!batchParsed.ok) return toast(`Bad batch JSON: ${batchParsed.error}`, "error");
  try {
    const result = await api("/dispense", { method: "POST", body: { prescription: rxParsed.value, batch: batchParsed.value } });
    $("dispense_out").value = pretty(result);
    toast("Dispense allowed", "success");
  } catch (err) {
    $("dispense_out").value = pretty({ ok: false, error: err.message });
    toast(`Dispense blocked: ${err.message}`, "error");
  }
}

function chainSanity(entries) {
  const asc = [...entries].sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
  let ok = true;
  for (let i = 1; i < asc.length; i++) {
    if (asc[i].prevHash !== asc[i - 1].hash) {
      ok = false;
      break;
    }
  }
  return { ok, count: asc.length };
}

async function onLoadAudit() {
  try {
    const result = await api("/audit/logs");
    const sanity = chainSanity(result.entries);
    const payload = {
      count: result.count,
      chainSanity: sanity,
      entries: result.entries,
    };
    window.__auditCache = payload;
    $("audit_out").value = pretty(payload);
    renderAuditReadable($("auditReadable"), payload);
    toast(sanity.ok ? "Audit loaded (chain links consistent)" : "Audit loaded (chain mismatch!)", sanity.ok ? "success" : "error");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onLoadUserAudit() {
  try {
    const selected = $("adminUserSelect").value || "";
    const action = $("adminActionFilter").value.trim();
    const [userId, username] = selected.split("|");
    const qs = new URLSearchParams();
    if (userId) qs.set("userId", userId);
    if (username) qs.set("username", username);
    if (action) qs.set("action", action);
    const result = await api(`/audit/logs?${qs.toString()}`);
    const sanity = chainSanity(result.entries);
    const counts = {};
    for (const e of result.entries) counts[e.action] = (counts[e.action] || 0) + 1;
    const payload = {
      scope: { userId, username, action: action || null },
      chainSanity: sanity,
      countsByAction: counts,
      entries: result.entries,
    };
    window.__adminUserAuditCache = payload;
    $("adminUserAuditOut").value = pretty(payload);
    renderAuditReadable($("adminUserAuditReadable"), payload);
    toast("User logs loaded", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onIssueClinicCode(e) {
  e.preventDefault();
  try {
    const patientId = $("cc_patientId").value.trim();
    const expiresMinutes = Number($("cc_expires").value);
    const sendEmail = Boolean($("cc_sendEmail").checked);
    const out = await api("/clinic/codes", {
      method: "POST",
      body: {
        patientId: patientId || undefined,
        expiresMinutes: Number.isFinite(expiresMinutes) ? expiresMinutes : 10,
        sendEmail,
      },
    });
    $("cc_code").textContent = out.code || "—";
    $("cc_expiry").textContent = out.expiresAt || "—";
    $("cc_delivery").textContent = out.delivery || "—";
    $("cc_sentTo").textContent = out.sentTo || "—";
    toast("Clinic code generated", "success");
    await onLoadPendingPatients();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onLoadPendingPatients() {
  try {
    const out = await api("/admin/patients?status=PENDING");
    const select = $("adminPendingSelect");
    select.innerHTML = "";
    if (!out.patients?.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No PENDING patients";
      select.appendChild(opt);
      return;
    }
    for (const p of out.patients) {
      const opt = document.createElement("option");
      opt.value = p.patientId;
      const username = p.user?.username || p.patientId;
      const email = p.user?.email || "—";
      opt.textContent = `${username} • score ${p.trustScore} • ${email} • ${p.patientId}`;
      select.appendChild(opt);
    }
    const firstId = out.patients[0].patientId;
    $("cc_patientId").value = firstId;
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onMailTest(e) {
  e.preventDefault();
  try {
    const to = $("mailTestTo").value.trim();
    const out = await api("/admin/mail/test", { method: "POST", body: { to } });
    toast(out.ok ? "Test email sent" : "Test email failed", out.ok ? "success" : "error");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onSmtpStatus() {
  try {
    const out = await api("/admin/mail/status");
    $("smtpStatusOut").textContent = out.ok ? "OK" : `NOT OK: ${out.error}`;
    toast(out.ok ? "SMTP verified" : `SMTP not OK: ${out.error}`, out.ok ? "success" : "error");
  } catch (err) {
    $("smtpStatusOut").textContent = `ERROR: ${err.message}`;
    toast(err.message, "error");
  }
}

async function refreshPatientProfile() {
  try {
    const out = await api("/patients/me/profile");
    $("patient_profile_out").value = pretty(out);
    $("patient_token").textContent = out.patientToken || "—";
    $("patient_did").textContent = out.profile?.did || "—";
    $("patient_mfa_email").value = out.user?.email || "";
    renderPatientProfileReadable(out);
    await refreshLoginDevices();
  } catch (err) {
    $("patient_profile_out").value = pretty({ ok: false, error: err.message });
    $("patientProfileReadable").innerHTML = `<span class="color-fg-muted text-small">${escapeHtml(err.message)}</span>`;
  }
}

async function refreshLoginDevices() {
  try {
    const out = await api("/auth/login-devices");
    window.__loginDevicesCache = out;
    $("loginDevices_out").value = pretty(out);
    renderLoginDevicesReadable(out);
  } catch (err) {
    $("loginDevices_out").value = pretty({ ok: false, error: err.message });
    $("loginDevicesReadable").innerHTML = `<span class="color-fg-muted text-small">${escapeHtml(err.message)}</span>`;
  }
}

async function onPatientIssueDid() {
  try {
    const out = await api("/patients/issue-did", { method: "POST", body: {} });
    $("patient_did").textContent = out.did || "—";
    toast("DID issued", "success");
    await refreshPatientProfile();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onPatientProvisionKey() {
  try {
    const out = await api("/patients/provision-data-key", { method: "POST", body: {} });
    $("patient_token").textContent = out.patientToken || $("patient_token").textContent;
    toast("Data key provisioned", "success");
    await refreshPatientProfile();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onBindDevice(e) {
  e.preventDefault();
  try {
    const body = {
      deviceId: $("bd_deviceId").value.trim(),
      publicKeyPem: $("bd_publicKeyPem").value,
      fingerprintHash: $("bd_fingerprint").value.trim() || undefined,
    };
    const out = await api("/patients/bind-device", { method: "POST", body });
    $("bd_out").value = pretty(out);
    $("bd_challenge").value = pretty({ deviceId: out.challenge?.deviceId, nonce: out.challenge?.nonce });
    toast("Challenge created. Sign it and verify.", "warning");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onVerifyDevice(e) {
  e.preventDefault();
  try {
    const challengeParsed = safeParseJson($("bd_challenge").value);
    if (!challengeParsed.ok) return toast(`Bad challenge JSON: ${challengeParsed.error}`, "error");
    const { deviceId } = challengeParsed.value || {};
    const signatureB64url = $("bd_signature").value.trim();
    const out = await api("/auth/device-verify", { method: "POST", body: { deviceId, signatureB64url } });
    $("bd_out").value = pretty(out);
    toast("Device verified (ACTIVE)", "success");
    await refreshPatientProfile();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onPatientEnableMfa(e) {
  e.preventDefault();
  try {
    const email = $("patient_mfa_email").value.trim();
    const out = await api("/patients/enable-mfa", { method: "POST", body: { method: "EMAIL_OTP", ...(email ? { email } : {}) } });
    toast(`MFA enabled: ${out.method}`, "success");
    await refreshPatientProfile();
  } catch (err) {
    toast(err.message, "error");
  }
}

let mfaDisablePending = null;

async function onMfaDisableRequest() {
  try {
    const out = await api("/patients/disable-mfa/request", { method: "POST", body: {} });
    mfaDisablePending = { otpRequestId: out.otpRequestId };
    $("mfaDisableOtpId").textContent = out.otpRequestId;
    $("mfaDisableBox").hidden = false;
    toast("Disable code sent to email.", "warning");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onMfaDisableConfirm() {
  try {
    if (!mfaDisablePending?.otpRequestId) return toast("No pending disable request.", "error");
    const otp = $("mfaDisableOtp").value.trim();
    await api("/patients/disable-mfa/confirm", { method: "POST", body: { otpRequestId: mfaDisablePending.otpRequestId, otp } });
    $("mfaDisableBox").hidden = true;
    $("mfaDisableOtp").value = "";
    mfaDisablePending = null;
    toast("MFA disabled", "success");
    await refreshPatientProfile();
  } catch (err) {
    toast(err.message, "error");
  }
}

let trustedRemovePending = null;

async function loadTrustedDevices() {
  const out = await api("/auth/trusted-devices");
  const select = $("trustedSelect");
  select.innerHTML = "";
  if (!out.devices?.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "No trusted devices";
    select.appendChild(opt);
    return;
  }
  for (const d of out.devices) {
    const opt = document.createElement("option");
    opt.value = d.deviceId;
    const last = d.lastUsedAt ? new Date(d.lastUsedAt).toLocaleString() : "—";
    const exp = d.expiresAt ? new Date(d.expiresAt).toLocaleDateString() : "—";
    opt.textContent = `${d.deviceId} • last ${last} • expires ${exp}`;
    select.appendChild(opt);
  }
}

async function onTrustedRefresh() {
  try {
    await loadTrustedDevices();
    toast("Trusted devices loaded", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onTrustedRemoveRequest() {
  try {
    const deviceId = $("trustedSelect").value;
    if (!deviceId) return toast("Select a device first.", "error");
    const out = await api("/auth/trusted-devices/remove/request", { method: "POST", body: { deviceId } });
    trustedRemovePending = { otpRequestId: out.otpRequestId, deviceId };
    $("trustedRemoveOtpId").textContent = out.otpRequestId;
    $("trustedRemoveOtpBox").hidden = false;
    toast("OTP sent to email. Enter it to confirm removal.", "warning");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onTrustedRemoveConfirm() {
  try {
    if (!trustedRemovePending?.otpRequestId) return toast("No pending removal request.", "error");
    const otp = $("trustedRemoveOtp").value.trim();
    const out = await api("/auth/trusted-devices/remove/confirm", { method: "POST", body: { otpRequestId: trustedRemovePending.otpRequestId, otp } });
    $("trustedRemoveOtpBox").hidden = true;
    $("trustedRemoveOtp").value = "";
    trustedRemovePending = null;
    toast(`Removed trusted device: ${out.deviceId}`, "success");
    await loadTrustedDevices();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function autoBindDevice() {
  const outEl = $("autoBindOut");
  try {
    const deviceId = getDeviceId();
    $("autoDeviceId").textContent = deviceId;
    outEl.value = pretty({ step: "start", deviceId });

    const { privateKey, publicKey } = await getOrCreateP256KeyPair();
    const publicKeyPem = await exportSpkiPem(publicKey);

    // 1) Get or create challenge
    let challenge = null;
    try {
      const ch = await api("/auth/device-challenge", { method: "POST", body: { deviceId } });
      if (ch.status === "active") {
        outEl.value = pretty({ ok: true, status: "already_active", deviceId });
        return;
      }
      challenge = ch.challenge;
    } catch (err) {
      // If the device isn't registered yet, bind it.
      if (!String(err.message).includes("device_not_found")) throw err;
    }

    if (!challenge) {
      try {
        const bind = await api("/patients/bind-device", {
          method: "POST",
          body: { deviceId, publicKeyPem, keyAlg: "ES256" },
        });
        if (bind.status === "active") {
          outEl.value = pretty({ ok: true, status: "already_active", deviceId });
          return;
        }
        challenge = bind.challenge;
      } catch (err) {
        // If the device already exists for this patient, fetch a fresh challenge and continue.
        if (!String(err.message).includes("device_exists")) throw err;
        const ch = await api("/auth/device-challenge", { method: "POST", body: { deviceId } });
        if (ch.status === "active") {
          outEl.value = pretty({ ok: true, status: "already_active", deviceId });
          return;
        }
        challenge = ch.challenge;
      }
    }

    // 2) Sign challenge and verify
    const payload = { deviceId: challenge.deviceId, nonce: challenge.nonce };
    const signatureB64url = await signEs256(privateKey, payload);
    const verify = await api("/auth/device-verify", { method: "POST", body: { deviceId, signatureB64url } });
    outEl.value = pretty({ ok: true, verify });
  } catch (err) {
    outEl.value = pretty({ ok: false, error: err.message });
    toast(err.message, "error");
  }
}

function wire() {
  $("tabLogin").addEventListener("click", () => setAccessTab("login"));
  $("tabRegister").addEventListener("click", () => setAccessTab("register"));

  $("loginForm").addEventListener("submit", onLogin);
  $("otpForm").addEventListener("submit", onVerifyOtp);
  $("otpResendBtn").addEventListener("click", onResendOtp);
  $("logoutBtn").addEventListener("click", onLogout);

  $("preRegisterForm").addEventListener("submit", onPreRegister);
  $("verifyClinicForm").addEventListener("submit", onVerifyClinicCode);

  $("rxForm").addEventListener("submit", onCreateRx);
  $("rxVerifyBtn").addEventListener("click", onVerifyRx);
  $("rxTamperBtn").addEventListener("click", onTamperRx);

  $("batchForm").addEventListener("submit", onCreateBatch);
  $("batchVerifyBtn").addEventListener("click", onVerifyBatch);
  $("batchTamperBtn").addEventListener("click", onTamperBatch);

  $("dispenseForm").addEventListener("submit", onDispense);
  $("pharmacyEnrollBtn").addEventListener("click", pharmacyEnrollBiometric);
  $("pharmacyVerifyBtn").addEventListener("click", pharmacyVerifyBiometric);
  $("auditLoadBtn").addEventListener("click", onLoadAudit);
  $("adminLoadUserAuditBtn").addEventListener("click", onLoadUserAudit);
  $("auditToggleJsonBtn").addEventListener("click", () => {
    const ta = $("audit_out");
    const showing = !ta.hidden;
    ta.hidden = showing;
    $("auditToggleJsonBtn").textContent = showing ? "Show JSON" : "Hide JSON";
  });
  $("auditCopyJsonBtn").addEventListener("click", async () => {
    const text = $("audit_out").value || pretty(window.__auditCache || {});
    await navigator.clipboard.writeText(text);
    toast("Copied audit JSON", "success");
  });
  $("adminUserAuditToggleJsonBtn").addEventListener("click", () => {
    const ta = $("adminUserAuditOut");
    const showing = !ta.hidden;
    ta.hidden = showing;
    $("adminUserAuditToggleJsonBtn").textContent = showing ? "Show JSON" : "Hide JSON";
  });
  $("adminUserAuditCopyJsonBtn").addEventListener("click", async () => {
    const text = $("adminUserAuditOut").value || pretty(window.__adminUserAuditCache || {});
    await navigator.clipboard.writeText(text);
    toast("Copied user audit JSON", "success");
  });
  $("clinicCodeForm").addEventListener("submit", onIssueClinicCode);
  $("adminLoadPendingBtn").addEventListener("click", onLoadPendingPatients);
  $("adminPendingSelect").addEventListener("change", () => {
    const val = $("adminPendingSelect").value;
    if (val) $("cc_patientId").value = val;
  });
  $("mailTestForm").addEventListener("submit", onMailTest);
  $("smtpStatusBtn").addEventListener("click", onSmtpStatus);
  $("cc_copy").addEventListener("click", async () => {
    const code = $("cc_code").textContent || "";
    await navigator.clipboard.writeText(code);
    toast("Copied clinic code", "success");
  });

  $("patientRefreshBtn").addEventListener("click", refreshPatientProfile);
  $("loginDevicesRefreshBtn").addEventListener("click", refreshLoginDevices);
  $("loginDevicesToggleJsonBtn").addEventListener("click", () => {
    const ta = $("loginDevices_out");
    const showing = !ta.hidden;
    ta.hidden = showing;
    $("loginDevicesToggleJsonBtn").textContent = showing ? "Show JSON" : "Hide JSON";
  });
  $("loginDevicesCopyJsonBtn").addEventListener("click", async () => {
    const text = $("loginDevices_out").value || pretty(window.__loginDevicesCache || {});
    await navigator.clipboard.writeText(text);
    toast("Copied login devices JSON", "success");
  });
  $("patientProfileToggleJsonBtn").addEventListener("click", () => {
    const ta = $("patient_profile_out");
    const showing = !ta.hidden;
    ta.hidden = showing;
    $("patientProfileToggleJsonBtn").textContent = showing ? "Show JSON" : "Hide JSON";
  });
  $("patientProfileCopyJsonBtn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("patient_profile_out").value || "");
    toast("Copied profile JSON", "success");
  });
  $("patientMfaForm").addEventListener("submit", onPatientEnableMfa);
  $("mfaDisableRequestBtn").addEventListener("click", onMfaDisableRequest);
  $("mfaDisableConfirmBtn").addEventListener("click", onMfaDisableConfirm);
  $("trustedRefreshBtn").addEventListener("click", onTrustedRefresh);
  $("trustedRemoveBtn").addEventListener("click", onTrustedRemoveRequest);
  $("trustedRemoveConfirmBtn").addEventListener("click", onTrustedRemoveConfirm);
  $("patientIssueDidBtn").addEventListener("click", onPatientIssueDid);
  $("patientProvisionKeyBtn").addEventListener("click", onPatientProvisionKey);

  $("autoBindBtn").addEventListener("click", autoBindDevice);

  $("copyRxBtn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("rx_out").value || "");
    toast("Copied Rx JSON", "success");
  });
  $("copyBatchBtn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("batch_out").value || "");
    toast("Copied batch JSON", "success");
  });
  $("useRxBtn").addEventListener("click", () => {
    $("dispense_rx").value = $("rx_out").value;
    toast("Loaded Rx into dispense form", "success");
  });
  $("useBatchBtn").addEventListener("click", () => {
    $("dispense_batch").value = $("batch_out").value;
    toast("Loaded batch into dispense form", "success");
  });
}

async function init() {
  wire();
  setAccessTab("login");
  await checkHealth();

  // Magic-link auto-consume (new device verification)
  const url = new URL(window.location.href);
  const magicToken = url.searchParams.get("mlt");
  if (magicToken) {
    try {
      const deviceId = getDeviceId();
      const out = await api("/auth/magic-link/consume", { method: "POST", body: { token: magicToken, deviceId } });
      setToken(out.token);
      toast("Device verified. Logged in.", "success");
      url.searchParams.delete("mlt");
      window.history.replaceState({}, "", url.toString());
    } catch (err) {
      toast(`Magic link failed: ${err.message}`, "error");
    }
  }

  await updateAuthUi();

  // Initialize toggle button labels (in case server-side render differs).
  $("auditToggleJsonBtn").textContent = $("audit_out").hidden ? "Show JSON" : "Hide JSON";
  $("adminUserAuditToggleJsonBtn").textContent = $("adminUserAuditOut").hidden ? "Show JSON" : "Hide JSON";
  $("patientProfileToggleJsonBtn").textContent = $("patient_profile_out").hidden ? "Show JSON" : "Hide JSON";

  const expiryEl = $("batch_expiry");
  if (expiryEl && !expiryEl.value) {
    const d = new Date();
    d.setFullYear(d.getFullYear() + 1);
    expiryEl.value = d.toISOString().slice(0, 10);
  }
}

init().catch((err) => {
  toast(err.message, "error");
});
