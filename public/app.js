function computeApiBase() {
  const explicit = typeof window.GZ_API_BASE === "string" ? window.GZ_API_BASE.trim() : "";
  const stored = (localStorage.getItem("gz_api_base") || "").trim();
  const isFirebaseHost =
    window.location.hostname.endsWith(".web.app") || window.location.hostname.endsWith(".firebaseapp.com");
  const auto = isFirebaseHost ? "https://genzipher.vercel.app" : "";
  const base = explicit || stored || auto || "";
  window.GZ_API_BASE = base;
  return base;
}

const API_BASE = computeApiBase();

function computeApiOrigin() {
  try {
    return API_BASE ? new URL(API_BASE).origin : window.location.origin;
  } catch {
    return window.location.origin;
  }
}

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

function getToken() {
  return localStorage.getItem("gz_token") || localStorage.getItem("auth_token");
}

function setToken(token) {
  if (!token) {
    localStorage.removeItem("gz_token");
    localStorage.removeItem("auth_token");
  } else {
    localStorage.setItem("gz_token", token);
    localStorage.setItem("auth_token", token);
  }
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

function setPendingResetState(state) {
  if (!state) localStorage.removeItem("gz_pending_reset");
  else localStorage.setItem("gz_pending_reset", JSON.stringify(state));
}

function getPendingResetState() {
  const raw = localStorage.getItem("gz_pending_reset");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function resetRemainingAttempts(maxAttempts, attemptsUsed) {
  const remaining = Math.max(0, Number(maxAttempts || 3) - Number(attemptsUsed || 0));
  const el = $("forgot_remaining");
  if (el) el.textContent = String(remaining);
}

async function api(path, { method = "GET", body } = {}) {
  const token = getToken();
  const deviceId = getDeviceId();
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(deviceId ? { "x-gz-device-id": deviceId } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (path === "/auth/forgot-password/verify-otp" && (data?.remainingAttempts !== undefined || data?.maxAttempts !== undefined)) {
      const maxA = Number(data?.maxAttempts || 3);
      const rem = Number(data?.remainingAttempts ?? 0);
      const used = Math.max(0, maxA - rem);
      resetRemainingAttempts(maxA, used);
    }
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

function toggleForgotBox(force) {
  const box = $("forgotBox");
  if (!box) return;
  const show = typeof force === "boolean" ? force : box.hidden;
  box.hidden = !show;
}

// Handle role-based routing
function handleRoleRouting(role) {
  const currentPath = window.location.pathname;
  const rolePaths = {
    doctor: "/doctor",
    pharmacy: "/pharmacy",
    patient: "/patient",
    manufacturer: "/manufacturer",
    admin: "/admin"
  };
  
  const expectedPath = rolePaths[role] || "/";
  
  // If user is on wrong role path, redirect them
  if (currentPath !== expectedPath && currentPath !== "/" && currentPath !== "/index.html") {
    // Check if current path is a role path
    const isRolePath = Object.values(rolePaths).includes(currentPath);
    if (isRolePath) {
      // User is on a different role's path, redirect to their role path
      window.history.replaceState({}, "", expectedPath);
    }
  }
  
  // Update URL if on root and logged in
  if ((currentPath === "/" || currentPath === "/index.html" || currentPath === "") && role) {
    window.history.replaceState({}, "", rolePaths[role] || "/");
  }
}

async function updateAuthUi() {
  const token = getToken();
  $("logoutBtn").hidden = !token;
  $("loginBox").hidden = Boolean(token);
  $("appBox").hidden = !token;
  
  // Update grid layout when workspace or login is shown
  const mainGrid = $("mainGrid");
  if (mainGrid) {
    if (token) {
      // Workspace is visible - use single column
      mainGrid.style.gridTemplateColumns = "1fr";
    } else {
      // Login is visible - use single column for full width
      mainGrid.style.gridTemplateColumns = "1fr";
    }
  }

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

    const pendingReset = getPendingResetState();
    if (pendingReset?.otpRequestId) {
      toggleForgotBox(true);
      $("forgotOtpBox").hidden = false;
      $("forgot_otp_id").textContent = pendingReset.otpRequestId;
      if (pendingReset.identifier) $("forgot_identifier").value = pendingReset.identifier;
    }
    return;
  }

  try {
    const whoami = await api("/demo/whoami");
    const auth = whoami.auth;
    $("whoami").textContent = `${auth.username} (${auth.role})`;
    $("currentRole").textContent = auth.role;
    showRole(auth.role);
    handleRoleRouting(auth.role);

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
    }

    if (auth.role === "patient") {
      await refreshPatientProfile();
      await loadDoctorsForBooking();
    } else if (auth.role === "pharmacy") {
      // Check biometric verification status
      try {
        const biometricStatus = await api("/pharmacy/biometric-status");
        if (!biometricStatus.biometricVerified) {
          // Show biometric verification page
          showBiometricVerificationPage();
          return;
        }
      } catch (err) {
        // If check fails, still try to show biometric page
        showBiometricVerificationPage();
        return;
      }
      
      // Biometric verified, load pharmacist dashboard
      if (typeof showPharmTab === "function") {
        showPharmTab("dashboard");
      }
    }
  } catch (err) {
    setToken(null);
    toast(`Session expired: ${err.message}`, "error");
  }
}

async function checkHealth() {
  try {
    await api("/health");
    setStatus(true, "API reachable");
  } catch {
    setStatus(false, "API not reachable (run server)");
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
    if (out.mfaRequired && out.method === "EMAIL_OTP") {
      setPendingOtpState({
        otpRequestId: out.otpRequestId,
        expiresAt: out.expiresAt,
        sentTo: out.sentTo,
        delivery: out.delivery,
        identifier,
        userId: out.userId,
      });
      $("otpBox").hidden = false;
      $("otp_expires").textContent = out.expiresAt || "—";
      $("otp_sentTo").textContent = out.sentTo || "—";
      toast("OTP required. Check server logs for code (MVP).", "warning");
      return;
    }
    setPendingOtpState(null);
    setToken(out.token);
    toast("Logged in", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onLogout() {
  try {
    const token = getToken();
    if (token) {
      // Call backend logout endpoint to clear biometric verification
      try {
        await api("/auth/logout", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } catch (err) {
        // Even if logout endpoint fails, continue with frontend logout
        console.warn("[LOGOUT] Backend logout failed:", err);
      }
    }
  } catch (err) {
    console.error("[LOGOUT] Error:", err);
  } finally {
    // Always clear frontend state
    setToken(null);
    setPendingOtpState(null);
    toast("Logged out", "success");
  }
}

async function onForgotRequest(e) {
  e.preventDefault();
  try {
    const identifier = $("forgot_identifier").value.trim();
    if (!identifier) return toast("Enter your username or email.", "error");

    const out = await api("/auth/forgot-password/request", {
      method: "POST",
      body: { identifier, deviceId: getDeviceId() },
    });

    if (out.otpRequestId) {
      setPendingResetState({ otpRequestId: out.otpRequestId, identifier, resetToken: null });
      $("forgotOtpBox").hidden = false;
      $("forgotSetBox").hidden = true;
      $("forgot_otp_id").textContent = out.otpRequestId;
      resetRemainingAttempts(3, 0);
      toast(out.delivery === "email" ? "OTP sent to your email." : "OTP issued. Check server logs (MVP).", "warning");
    } else {
      toast("If that account exists and has an email, you’ll receive a code shortly.", "success");
    }
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onForgotConfirm(e) {
  e.preventDefault();
  try {
    const pending = getPendingResetState();
    if (!pending?.otpRequestId) return toast("No pending reset request.", "error");
    const otp = $("forgot_otp").value.trim();
    const out = await api("/auth/forgot-password/verify-otp", {
      method: "POST",
      body: { otpRequestId: pending.otpRequestId, otp },
    });
    setPendingResetState({ ...pending, resetToken: out.resetToken });
    $("forgotOtpBox").hidden = true;
    $("forgotSetBox").hidden = false;
    toast("OTP verified. Set a new password.", "success");
  } catch (err) {
    // Try to extract remaining attempts from the error message payload (api() throws string only).
    // We don't have structured errors here, so show the generic message.
    toast(err.message, "error");
  }
}

async function onForgotResend() {
  const pending = getPendingResetState();
  if (!pending?.otpRequestId) return toast("No pending reset request.", "error");
  try {
    const out = await api("/auth/resend-otp", { method: "POST", body: { otpRequestId: pending.otpRequestId } });
    toast(`OTP resent (${out.delivery}).`, "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onForgotSet(e) {
  e.preventDefault();
  try {
    const pending = getPendingResetState();
    if (!pending?.resetToken) return toast("Verify OTP first.", "error");
    const newPassword = $("forgot_new_password").value;
    if (!newPassword || newPassword.length < 8) return toast("New password must be at least 8 characters.", "error");
    await api("/auth/forgot-password/set-password", { method: "POST", body: { resetToken: pending.resetToken, newPassword } });
    setPendingResetState(null);
    $("forgotSetBox").hidden = true;
    $("forgot_new_password").value = "";
    toast("Password reset. You can login now.", "success");
    $("login_identifier").value = pending.identifier || $("login_identifier").value;
    $("login_password").value = "";
  } catch (err) {
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
    };
    const out = await api("/patients/pre-register", { method: "POST", body });
    $("pr_out").value = pretty(out);
    if (out.patientId) {
      $("vc_patientId").value = out.patientId;
      $("vc_username").value = body.username;
    }
    toast(`Pre-registered: ${out.status} (score ${out.trustScore})`, out.status === "PENDING" ? "warning" : "success");
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

// Temporary medicines database (will be replaced with API later)
const MEDICINES_DATABASE = [
  { name: "Amoxicillin", commonDosages: ["250mg", "500mg"], defaultDosage: "500mg", defaultDuration: 7 },
  { name: "Paracetamol", commonDosages: ["500mg", "1000mg"], defaultDosage: "500mg", defaultDuration: 5 },
  { name: "Ibuprofen", commonDosages: ["200mg", "400mg"], defaultDosage: "400mg", defaultDuration: 7 },
  { name: "Aspirin", commonDosages: ["75mg", "100mg", "300mg"], defaultDosage: "100mg", defaultDuration: 30 },
  { name: "Metformin", commonDosages: ["500mg", "850mg", "1000mg"], defaultDosage: "500mg", defaultDuration: 30 },
  { name: "Atorvastatin", commonDosages: ["10mg", "20mg", "40mg"], defaultDosage: "20mg", defaultDuration: 30 },
  { name: "Omeprazole", commonDosages: ["20mg", "40mg"], defaultDosage: "20mg", defaultDuration: 14 },
  { name: "Amlodipine", commonDosages: ["5mg", "10mg"], defaultDosage: "5mg", defaultDuration: 30 },
  { name: "Levothyroxine", commonDosages: ["25mcg", "50mcg", "75mcg", "100mcg"], defaultDosage: "50mcg", defaultDuration: 30 },
  { name: "Metoprolol", commonDosages: ["25mg", "50mg", "100mg"], defaultDosage: "50mg", defaultDuration: 30 },
  { name: "Losartan", commonDosages: ["25mg", "50mg", "100mg"], defaultDosage: "50mg", defaultDuration: 30 },
  { name: "Sertraline", commonDosages: ["50mg", "100mg"], defaultDosage: "50mg", defaultDuration: 30 },
  { name: "Ciprofloxacin", commonDosages: ["250mg", "500mg"], defaultDosage: "500mg", defaultDuration: 7 },
  { name: "Azithromycin", commonDosages: ["250mg", "500mg"], defaultDosage: "500mg", defaultDuration: 5 },
  { name: "Cephalexin", commonDosages: ["250mg", "500mg"], defaultDosage: "500mg", defaultDuration: 7 },
];

// Medicine management for prescriptions
let medicinesList = [];

function searchMedicines(query) {
  if (!query || query.trim().length < 2) return [];
  const searchTerm = query.toLowerCase().trim();
  return MEDICINES_DATABASE.filter(med => 
    med.name.toLowerCase().includes(searchTerm)
  ).slice(0, 8); // Limit to 8 results
}

function showMedicineSearchResults(results) {
  const resultsContainer = $("rx_medicineSearchResults");
  if (results.length === 0) {
    resultsContainer.style.display = "none";
    return;
  }
  
  resultsContainer.innerHTML = "";
  results.forEach(med => {
    const item = document.createElement("div");
    item.className = "p-2 border-bottom";
    item.style.cursor = "pointer";
    item.innerHTML = `
      <div class="d-flex flex-justify-between flex-items-center">
        <div>
          <strong>${med.name}</strong>
          <div class="text-small color-fg-muted">Common dosages: ${med.commonDosages.join(", ")}</div>
        </div>
        <button type="button" class="btn btn-sm btn-primary" data-medicine='${JSON.stringify(med)}'>Add</button>
      </div>
    `;
    item.addEventListener("click", (e) => {
      if (e.target.tagName === "BUTTON" || e.target.closest("button")) {
        const btn = e.target.closest("button");
        const medicine = JSON.parse(btn.dataset.medicine);
        addMedicineToTable({
          medicineName: medicine.name,
          dosage: medicine.defaultDosage,
          durationDays: medicine.defaultDuration,
        });
        $("rx_medicineSearch").value = "";
        resultsContainer.style.display = "none";
      }
    });
    item.addEventListener("mouseenter", () => {
      item.style.backgroundColor = "var(--bgColor-muted)";
    });
    item.addEventListener("mouseleave", () => {
      item.style.backgroundColor = "";
    });
    resultsContainer.appendChild(item);
  });
  resultsContainer.style.display = "block";
}

function addMedicineToTable(medicine = { medicineName: "", dosage: "", durationDays: 7 }) {
  medicinesList.push(medicine);
  renderMedicinesTable();
}

function removeMedicineFromTable(index) {
  medicinesList.splice(index, 1);
  renderMedicinesTable();
}

// Expose to global scope for onclick handlers
window.removeMedicineFromTable = removeMedicineFromTable;

function renderMedicinesTable() {
  const tbody = $("rx_medicinesTbody");
  const noMedicines = $("rx_noMedicines");
  const submitBtn = $("rx_submitBtn");
  
  tbody.innerHTML = "";
  
  if (medicinesList.length === 0) {
    noMedicines.style.display = "block";
    submitBtn.disabled = true;
    return;
  }
  
  noMedicines.style.display = "none";
  submitBtn.disabled = false;
  
  medicinesList.forEach((med, index) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>
        <input type="text" class="form-control form-control-sm" value="${med.medicineName || ""}" 
               placeholder="Amoxicillin" data-index="${index}" data-field="medicineName" />
      </td>
      <td>
        <input type="text" class="form-control form-control-sm" value="${med.dosage || ""}" 
               placeholder="500mg" data-index="${index}" data-field="dosage" />
      </td>
      <td>
        <input type="number" class="form-control form-control-sm" value="${med.durationDays || 7}" 
               placeholder="7" min="1" data-index="${index}" data-field="durationDays" />
      </td>
      <td>
        <button type="button" class="btn btn-sm btn-danger" onclick="removeMedicineFromTable(${index})">Remove</button>
      </td>
    `;
    tbody.appendChild(row);
  });
  
  // Add event listeners for inline editing
  tbody.querySelectorAll("input").forEach(input => {
    input.addEventListener("change", (e) => {
      const index = parseInt(e.target.dataset.index);
      const field = e.target.dataset.field;
      if (field === "durationDays") {
        medicinesList[index][field] = Number(e.target.value) || 7;
      } else if (field === "medicineName") {
        medicinesList[index].medicineName = e.target.value.trim();
      } else {
        medicinesList[index][field] = e.target.value.trim();
      }
    });
  });
}

async function onCreateRx(e) {
  e.preventDefault();
  try {
    const patientUserId = $("rx_patientUserId").value;
    if (!patientUserId) {
      toast("Please select a patient", "error");
      return;
    }
    
    if (medicinesList.length === 0) {
      toast("Please add at least one medicine", "error");
      return;
    }
    
    // Validate all medicines
    const medicines = medicinesList.map((med, idx) => {
      if (!med.medicineName || !med.dosage || !med.durationDays) {
        throw new Error(`Medicine ${idx + 1} is incomplete. Please fill all fields.`);
      }
      return {
        medicineName: med.medicineName.trim(),
        dosage: med.dosage.trim(),
        durationDays: Number(med.durationDays) || 7,
      };
    });
    
    const body = {
      patientUserId,
      medicines, // Send as array
    };
    
    const result = await api("/prescriptions", { method: "POST", body });
    $("rx_out").value = pretty(result);
    toast(`Prescription signed with ${medicines.length} medicine(s)`, "success");
    
    // Clear medicines list after successful creation
    medicinesList = [];
    renderMedicinesTable();
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
  } catch (err) {
    $("patient_profile_out").value = pretty({ ok: false, error: err.message });
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

// Show biometric verification page for pharmacy users
function showBiometricVerificationPage() {
  // Hide all role panes
  document.querySelectorAll('[id^="role_"]').forEach(el => el.hidden = true);
  
  // Show or create biometric verification pane
  let bioPane = document.getElementById("biometricVerificationPane");
  if (!bioPane) {
    // Create the pane if it doesn't exist
    const rolePharmacy = document.getElementById("role_pharmacy");
    if (rolePharmacy) {
      bioPane = document.createElement("div");
      bioPane.id = "biometricVerificationPane";
      bioPane.className = "Box p-3";
      bioPane.innerHTML = `
        <h3 class="f5 mb-3">Biometric Verification Required</h3>
        <p class="color-fg-muted mb-3">Please complete biometric verification to access the pharmacy dashboard.</p>
        <div id="biometricVerificationStatus" class="mb-3"></div>
        <div class="d-flex gap-2">
          <button id="biometricEnrollBtn" class="btn" style="display: none;">Enroll Biometric</button>
          <button id="biometricVerifyBtn" class="btn btn-primary">Start Biometric Verification</button>
        </div>
        <p class="text-small color-fg-muted mt-3">
          <strong>Note:</strong> This will use your device's fingerprint scanner or face recognition.
          Make sure your browser has permission to access biometrics.
        </p>
      `;
      rolePharmacy.insertBefore(bioPane, rolePharmacy.firstChild);
    }
  }
  
  if (bioPane) {
    bioPane.hidden = false;
    document.getElementById("role_pharmacy").hidden = false;
    
    // Wire up the buttons
    const verifyBtn = document.getElementById("biometricVerifyBtn");
    const enrollBtn = document.getElementById("biometricEnrollBtn");
    
    if (verifyBtn && !verifyBtn.dataset.wired) {
      verifyBtn.dataset.wired = "true";
      verifyBtn.addEventListener("click", handlePharmacyBiometricVerification);
    }
    
    if (enrollBtn && !enrollBtn.dataset.wired) {
      enrollBtn.dataset.wired = "true";
      enrollBtn.addEventListener("click", handlePharmacyBiometricEnrollment);
    }
    
    // Check enrollment status
    checkBiometricStatus();
  }
}

// Check biometric enrollment status
async function checkBiometricStatus() {
  try {
    const status = await api("/biometric/status");
    const enrollBtn = document.getElementById("biometricEnrollBtn");
    const verifyBtn = document.getElementById("biometricVerifyBtn");
    const statusEl = document.getElementById("biometricVerificationStatus");
    
    if (!status.enrolled || status.biometrics.length === 0) {
      if (enrollBtn) {
        enrollBtn.hidden = false;
        enrollBtn.classList.add("btn-primary");
        // Some templates used `style="display:none"`; ensure it's actually visible.
        enrollBtn.style.display = "";
      }
      if (verifyBtn) verifyBtn.disabled = true;
      if (statusEl) statusEl.textContent = "No biometric enrolled. Please enroll first.";
    } else {
      if (enrollBtn) {
        enrollBtn.hidden = true;
        enrollBtn.style.display = "none";
      }
      if (verifyBtn) verifyBtn.disabled = false;
      if (statusEl) statusEl.textContent = `Biometric enrolled. ${status.biometrics.length} device(s) registered.`;
    }
  } catch (err) {
    // If error, show enroll button
    const enrollBtn = document.getElementById("biometricEnrollBtn");
    if (enrollBtn) {
      enrollBtn.hidden = false;
      enrollBtn.classList.add("btn-primary");
      enrollBtn.style.display = "";
    }
  }
}

// Handle biometric enrollment (registration) for pharmacy users
async function handlePharmacyBiometricEnrollment() {
  const statusEl = document.getElementById("biometricVerificationStatus");
  const btn = document.getElementById("biometricEnrollBtn");
  
  try {
    btn.disabled = true;
    statusEl.textContent = "Starting biometric enrollment...";
    
    // Check if WebAuthn is supported
    if (!window.PublicKeyCredential) {
      throw new Error("WebAuthn is not supported in this browser. Please use a modern browser with biometric support.");
    }

    // 1) Get enrollment challenge from server
    statusEl.textContent = "Requesting enrollment challenge...";
    const enrollmentOptions = await api("/biometric/enroll/start", { method: "POST" });

    // 2) Convert base64url challenge to ArrayBuffer
    const challengeBuffer = Uint8Array.from(atob(enrollmentOptions.challenge.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const userIdBuffer = Uint8Array.from(atob(enrollmentOptions.user.id.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

    // 3) Prepare credential creation options
    const publicKeyCredentialCreationOptions = {
      challenge: challengeBuffer,
      rp: enrollmentOptions.rp,
      user: {
        id: userIdBuffer,
        name: enrollmentOptions.user.name,
        displayName: enrollmentOptions.user.displayName,
      },
      pubKeyCredParams: enrollmentOptions.pubKeyCredParams,
      authenticatorSelection: enrollmentOptions.authenticatorSelection,
      timeout: enrollmentOptions.timeout,
      attestation: enrollmentOptions.attestation,
    };

    // 4) Trigger biometric scanner (this will show browser's biometric popup)
    statusEl.textContent = "Please scan your fingerprint or face...";
    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions
    });

    // 5) Convert credential to sendable format
    const credentialForServer = {
      id: credential.id,
      rawId: Array.from(new Uint8Array(credential.rawId)),
      response: {
        attestationObject: Array.from(new Uint8Array(credential.response.attestationObject)),
        clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
      },
      type: credential.type,
    };

    // 6) Send credential to server
    statusEl.textContent = "Completing enrollment...";
    const result = await api("/biometric/enroll/complete", {
      method: "POST",
      body: {
        credential: credentialForServer,
        challenge: enrollmentOptions.challenge,
        deviceName: "Primary Device",
      },
    });

    if (result.ok) {
      statusEl.textContent = "✅ Biometric enrolled successfully! You can now use it for verification.";
      toast("Biometric enrolled successfully!", "success");
      // After enrollment, automatically verify
      setTimeout(() => {
        handlePharmacyBiometricVerification();
      }, 1000);
    }
  } catch (err) {
    statusEl.textContent = `❌ Error: ${err.message}`;
    toast(err.message, "error");
    if (btn) btn.disabled = false;
  }
}

// Handle biometric verification for pharmacy users
async function handlePharmacyBiometricVerification() {
  const statusEl = document.getElementById("biometricVerificationStatus");
  const btn = document.getElementById("biometricVerifyBtn");
  
  try {
    if (btn) btn.disabled = true;
    statusEl.textContent = "Starting biometric verification...";
    
    // Check if WebAuthn is supported
    if (!window.PublicKeyCredential) {
      throw new Error("WebAuthn is not supported in this browser. Please use a modern browser with biometric support.");
    }

    // 1) Check if biometric is enrolled
    const status = await api("/biometric/status");
    if (!status.enrolled || status.biometrics.length === 0) {
      statusEl.textContent = "No biometric enrolled. Please enroll first.";
      // Show enrollment button
      const enrollBtn = document.getElementById("biometricEnrollBtn");
      if (enrollBtn) {
        enrollBtn.hidden = false;
        enrollBtn.disabled = false;
        enrollBtn.style.display = "";
      }
      if (btn) btn.disabled = false;
      return;
    }

    // 2) Get verification challenge from server
    statusEl.textContent = "Requesting verification challenge...";
    const verificationOptions = await api("/biometric/verify/start", { method: "POST" });

    // 3) Convert base64url challenge to ArrayBuffer
    const challengeBuffer = Uint8Array.from(atob(verificationOptions.challenge.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    
    // 4) Convert allowCredentials
    const allowCredentials = verificationOptions.allowCredentials.map(cred => ({
      id: Uint8Array.from(atob(cred.id.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)),
      type: cred.type,
    }));

    // 5) Prepare assertion options
    const publicKeyCredentialRequestOptions = {
      challenge: challengeBuffer,
      allowCredentials: allowCredentials,
      timeout: verificationOptions.timeout,
      rpId: verificationOptions.rpId,
      userVerification: verificationOptions.userVerification,
    };

    // 6) Trigger biometric scanner (this will show browser's biometric popup)
    statusEl.textContent = "Please scan your fingerprint or face...";
    const assertion = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    });

    // 7) Convert assertion to sendable format
    const assertionForServer = {
      id: assertion.id,
      rawId: Array.from(new Uint8Array(assertion.rawId)),
      response: {
        authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
        clientDataJSON: Array.from(new Uint8Array(assertion.response.clientDataJSON)),
        signature: Array.from(new Uint8Array(assertion.response.signature)),
        userHandle: assertion.response.userHandle ? Array.from(new Uint8Array(assertion.response.userHandle)) : null,
      },
      type: assertion.type,
    };

    // 8) Send assertion to server
    statusEl.textContent = "Verifying biometric...";
    const verify = await api("/biometric/verify/complete", {
      method: "POST",
      body: {
        credential: assertionForServer,
        challenge: verificationOptions.challenge,
      },
    });
    
    if (verify.biometricVerified) {
      statusEl.textContent = "✅ Biometric verification successful! Redirecting to dashboard...";
      setTimeout(() => {
        document.getElementById("biometricVerificationPane").hidden = true;
        if (typeof showPharmTab === "function") {
          showPharmTab("dashboard");
        }
        updateAuthUi();
      }, 1500);
    } else {
      throw new Error("Biometric verification failed");
    }
  } catch (err) {
    statusEl.textContent = `❌ Error: ${err.message}`;
    toast(err.message, "error");
    if (btn) btn.disabled = false;
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
  $("forgotToggleBtn")?.addEventListener("click", () => toggleForgotBox());
  $("forgotRequestForm")?.addEventListener("submit", onForgotRequest);
  $("forgotConfirmForm")?.addEventListener("submit", onForgotConfirm);
  $("forgotResendBtn")?.addEventListener("click", onForgotResend);
  $("forgotSetForm")?.addEventListener("submit", onForgotSet);
  $("otpForm").addEventListener("submit", onVerifyOtp);
  $("otpResendBtn").addEventListener("click", onResendOtp);
  $("logoutBtn").addEventListener("click", onLogout);

  $("preRegisterForm").addEventListener("submit", onPreRegister);
  $("verifyClinicForm").addEventListener("submit", onVerifyClinicCode);

  $("rxForm").addEventListener("submit", onCreateRx);
  
  // Medicine search functionality
  const medicineSearchInput = $("rx_medicineSearch");
  if (medicineSearchInput) {
    let searchTimeout;
    medicineSearchInput.addEventListener("input", (e) => {
      clearTimeout(searchTimeout);
      const query = e.target.value;
      searchTimeout = setTimeout(() => {
        if (query.trim().length >= 2) {
          const results = searchMedicines(query);
          showMedicineSearchResults(results);
        } else {
          $("rx_medicineSearchResults").style.display = "none";
        }
      }, 300); // Debounce search
    });
    
    // Hide results when clicking outside
    document.addEventListener("click", (e) => {
      if (!e.target.closest("#rx_medicineSearch") && !e.target.closest("#rx_medicineSearchResults")) {
        $("rx_medicineSearchResults").style.display = "none";
      }
    });
    
    // Initialize medicines table
    renderMedicinesTable();
  }
  $("rxVerifyBtn").addEventListener("click", onVerifyRx);
  $("rxTamperBtn").addEventListener("click", onTamperRx);

  $("batchForm").addEventListener("submit", onCreateBatch);
  $("batchVerifyBtn").addEventListener("click", onVerifyBatch);
  $("batchTamperBtn").addEventListener("click", onTamperBatch);

  $("dispenseForm").addEventListener("submit", onDispense);
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
  $("patientMfaForm").addEventListener("submit", onPatientEnableMfa);
  $("mfaDisableRequestBtn").addEventListener("click", onMfaDisableRequest);
  $("mfaDisableConfirmBtn").addEventListener("click", onMfaDisableConfirm);
  $("trustedRefreshBtn").addEventListener("click", onTrustedRefresh);
  $("trustedRemoveBtn").addEventListener("click", onTrustedRemoveRequest);
  $("trustedRemoveConfirmBtn").addEventListener("click", onTrustedRemoveConfirm);
  $("patientIssueDidBtn").addEventListener("click", onPatientIssueDid);
  $("patientProvisionKeyBtn").addEventListener("click", onPatientProvisionKey);

  $("autoBindBtn").addEventListener("click", autoBindDevice);
  
  // Appointment booking
  $("appointmentForm").addEventListener("submit", onCreateAppointment);
  $("loadAppointmentsBtn").addEventListener("click", onLoadAppointments);
  
  // Doctor patient search
  $("tabRx").addEventListener("click", () => {
    $("doctorRxPane").hidden = false;
    $("doctorPatientSearchPane").hidden = true;
    $("tabRx").classList.add("btn-primary");
    $("tabPatientSearch").classList.remove("btn-primary");
  });
  $("tabPatientSearch").addEventListener("click", () => {
    $("doctorRxPane").hidden = true;
    $("doctorPatientSearchPane").hidden = false;
    $("tabRx").classList.remove("btn-primary");
    $("tabPatientSearch").classList.add("btn-primary");
    loadDoctorsForSearch();
  });
  
  let patientSearchTimeout;
  $("doctor_patientSearch").addEventListener("input", (e) => {
    clearTimeout(patientSearchTimeout);
    const query = e.target.value.trim();
    if (query.length < 2) {
      $("doctor_patientSearchResults").style.display = "none";
      return;
    }
    patientSearchTimeout = setTimeout(() => onSearchPatients(query), 300);
  });
  
  $("doctor_viewHistoryBtn").addEventListener("click", onViewPatientHistory);
  $("doctor_viewPrescriptionsBtn").addEventListener("click", onViewPatientPrescriptions);

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

// Appointment functions
let selectedPatientId = null;

async function onCreateAppointment(e) {
  e.preventDefault();
  try {
    const body = {
      doctorId: $("apt_doctorId").value,
      appointmentDate: $("apt_date").value,
      appointmentTime: $("apt_time").value,
      notes: $("apt_notes").value.trim() || null,
    };
    const appointment = await api("/appointments", { method: "POST", body });
    $("apt_out").innerHTML = `<div class="flash flash-success">Appointment booked successfully!</div><pre class="gz-json mt-2">${pretty(appointment)}</pre>`;
    $("appointmentForm").reset();
    await onLoadAppointments();
    toast("Appointment booked", "success");
  } catch (err) {
    $("apt_out").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
    toast(err.message, "error");
  }
}

async function onLoadAppointments() {
  try {
    const data = await api("/appointments");
    const list = $("appointmentsList");
    if (data.appointments.length === 0) {
      list.innerHTML = '<div class="color-fg-muted text-small">No appointments found.</div>';
      return;
    }
    list.innerHTML = data.appointments.map(apt => `
      <div class="Box p-2 mb-2">
        <div class="d-flex flex-justify-between flex-items-center">
          <div>
            <strong>Doctor ID:</strong> ${apt.doctorId}<br>
            <strong>Date:</strong> ${apt.appointmentDate} at ${apt.appointmentTime}<br>
            <strong>Status:</strong> <span class="Label Label--${apt.status === 'completed' ? 'success' : apt.status === 'cancelled' ? 'danger' : 'info'}">${apt.status}</span>
          </div>
        </div>
        ${apt.notes ? `<div class="mt-1 text-small color-fg-muted">Notes: ${apt.notes}</div>` : ''}
      </div>
    `).join("");
  } catch (err) {
    $("appointmentsList").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
    toast(err.message, "error");
  }
}

async function loadDoctorsForBooking() {
  try {
    const data = await api("/doctors");
    const select = $("apt_doctorId");
    if (!select) return; // Element might not exist if not patient role
    
    select.innerHTML = '<option value="">Select a doctor...</option>';
    
    if (data.doctors && data.doctors.length > 0) {
      data.doctors.forEach(doc => {
        const option = document.createElement("option");
        option.value = doc.id;
        option.textContent = `${doc.username} (${doc.id})`;
        select.appendChild(option);
      });
    } else {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No doctors available";
      option.disabled = true;
      select.appendChild(option);
    }
  } catch (err) {
    toast(err.message, "error");
    const select = $("apt_doctorId");
    if (select) {
      select.innerHTML = '<option value="">Error loading doctors</option>';
    }
  }
}

// Doctor patient search functions
async function onSearchPatients(query) {
  try {
    const data = await api(`/doctors/patients/search?query=${encodeURIComponent(query)}`);
    const resultsContainer = $("doctor_patientSearchResults");
    
    if (data.patients.length === 0) {
      resultsContainer.style.display = "none";
      return;
    }
    
    resultsContainer.innerHTML = "";
    data.patients.forEach(patient => {
      const item = document.createElement("div");
      item.className = "p-2 border-bottom";
      item.style.cursor = "pointer";
      item.innerHTML = `
        <div>
          <strong>${patient.username}</strong>
          <div class="text-small color-fg-muted">ID: ${patient.id}</div>
        </div>
      `;
      item.addEventListener("click", () => {
        selectedPatientId = patient.id;
        $("doctor_patientSearch").value = patient.username;
        resultsContainer.style.display = "none";
        showPatientDetails(patient);
      });
      item.addEventListener("mouseenter", () => {
        item.style.backgroundColor = "var(--bgColor-muted)";
      });
      item.addEventListener("mouseleave", () => {
        item.style.backgroundColor = "";
      });
      resultsContainer.appendChild(item);
    });
    resultsContainer.style.display = "block";
  } catch (err) {
    toast(err.message, "error");
  }
}

function showPatientDetails(patient) {
  const details = $("doctor_patientDetails");
  const info = $("doctor_patientInfo");
  info.innerHTML = `
    <div><strong>Patient:</strong> ${patient.username}</div>
    <div class="text-small color-fg-muted">ID: ${patient.id}</div>
  `;
  details.style.display = "block";
  $("doctor_patientData").innerHTML = "";
}

async function onViewPatientHistory() {
  if (!selectedPatientId) {
    toast("Please select a patient first", "error");
    return;
  }
  try {
    const data = await api(`/patients/${selectedPatientId}/history`);
    const container = $("doctor_patientData");
    container.innerHTML = `
      <h5 class="f6 mb-2">Patient History</h5>
      <div class="Box p-2 mb-2">
        <strong>Vitals Records:</strong> ${data.vitals.length}
        <ul class="mt-1">
          ${data.vitals.map(v => `<li class="text-small">${v.ts} - Device: ${v.deviceId}</li>`).join("")}
        </ul>
      </div>
      <div class="Box p-2">
        <strong>Appointments:</strong> ${data.appointments.length}
        <ul class="mt-1">
          ${data.appointments.map(a => `<li class="text-small">${a.appointmentDate} ${a.appointmentTime} - ${a.status}</li>`).join("")}
        </ul>
      </div>
      <pre class="gz-json mt-2">${pretty(data)}</pre>
    `;
    toast("Patient history loaded", "success");
  } catch (err) {
    toast(err.message, "error");
    $("doctor_patientData").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
  }
}

async function onViewPatientPrescriptions() {
  if (!selectedPatientId) {
    toast("Please select a patient first", "error");
    return;
  }
  try {
    const data = await api(`/patients/${selectedPatientId}/prescriptions`);
    const container = $("doctor_patientData");
    container.innerHTML = `
      <h5 class="f6 mb-2">Patient Prescriptions</h5>
      <div class="Box p-2">
        <strong>Total Prescriptions:</strong> ${data.prescriptions.length}
        <div class="mt-2">
          ${data.prescriptions.map(rx => `
            <div class="border-bottom pb-2 mb-2">
              <div><strong>${rx.medicineName}</strong></div>
              <div class="text-small">Dosage: ${rx.dosage}, Duration: ${rx.durationDays} days</div>
              <div class="text-small color-fg-muted">Issued: ${rx.issuedAt}, Status: ${rx.status}</div>
            </div>
          `).join("")}
        </div>
      </div>
      <pre class="gz-json mt-2">${pretty(data)}</pre>
    `;
    toast("Patient prescriptions loaded", "success");
  } catch (err) {
    toast(err.message, "error");
    $("doctor_patientData").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
  }
}

async function loadDoctorsForSearch() {
  // This is just to ensure doctors are available if needed
  // The search endpoint handles the filtering
}

// Pharmacist Dashboard Functions
function showPharmTab(tab) {
  const tabs = ["dashboard", "medicines", "stock", "quality", "dispense"];
  tabs.forEach(t => {
    const pane = $(`pharm${t.charAt(0).toUpperCase() + t.slice(1)}Pane`);
    const btn = $(`pharmTab${t.charAt(0).toUpperCase() + t.slice(1)}`);
    if (pane) pane.hidden = t !== tab;
    if (btn) {
      btn.classList.toggle("btn-primary", t === tab);
      btn.classList.toggle("btn-sm", true);
    }
  });
  
  // Load data when tab is shown
  if (tab === "dashboard") onLoadPharmDashboard();
  else if (tab === "medicines") onLoadPharmMedicines();
  else if (tab === "stock") onLoadPharmStock();
  else if (tab === "quality") onLoadPharmQuality();
}

async function onLoadPharmDashboard() {
  try {
    const data = await api("/pharmacy/dashboard");
    const stats = data.statistics;
    if ($("pharmStatMedicines")) $("pharmStatMedicines").textContent = stats.totalMedicines || 0;
    if ($("pharmStatStock")) $("pharmStatStock").textContent = stats.totalStockItems || 0;
    if ($("pharmStatLowStock")) $("pharmStatLowStock").textContent = stats.lowStockItems || 0;
    if ($("pharmStatExpired")) $("pharmStatExpired").textContent = stats.expiredItems || 0;
    if ($("pharmStatPending")) $("pharmStatPending").textContent = stats.pendingVerifications || 0;
  } catch (err) {
    toast(err.message, "error");
  }
}

// Medicines Management
async function onLoadPharmMedicines() {
  try {
    const search = $("pharmMedicineSearch")?.value || "";
    const category = $("pharmMedicineCategory")?.value || "";
    let url = "/pharmacy/medicines?";
    if (search) url += `search=${encodeURIComponent(search)}&`;
    if (category) url += `category=${encodeURIComponent(category)}&`;
    
    const data = await api(url);
    const container = $("pharmMedicinesList");
    if (!container) return;
    
    if (data.medicines.length === 0) {
      container.innerHTML = '<div class="color-fg-muted text-small">No medicines found.</div>';
      return;
    }
    
    container.innerHTML = data.medicines.map(med => `
      <div class="Box p-2 mb-2">
        <div class="d-flex flex-justify-between flex-items-center">
          <div>
            <strong>${med.name}</strong>
            ${med.genericName ? `<div class="text-small color-fg-muted">${med.genericName}</div>` : ''}
            <div class="text-small">Manufacturer: ${med.manufacturer} | Category: ${med.category}</div>
            ${med.strengths.length > 0 ? `<div class="text-small">Strengths: ${med.strengths.join(", ")}</div>` : ''}
          </div>
          <div class="d-flex gap-2">
            <button class="btn btn-sm" onclick="editPharmMedicine('${med.id}')">Edit</button>
            <span class="Label Label--${med.status === 'active' ? 'success' : 'danger'}">${med.status}</span>
          </div>
        </div>
      </div>
    `).join("");
  } catch (err) {
    toast(err.message, "error");
    if ($("pharmMedicinesList")) $("pharmMedicinesList").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
  }
}

async function onSearchPharmMedicines() {
  await onLoadPharmMedicines();
}

function showPharmMedicineModal(medicineId = null) {
  const modal = $("pharmMedicineModal");
  const form = $("pharmMedicineForm");
  if (!modal || !form) return;
  
  modal.style.display = "block";
  if (medicineId) {
    $("pharmMedicineModalTitle").textContent = "Edit Medicine";
    // Load medicine data
    loadPharmMedicineData(medicineId);
  } else {
    $("pharmMedicineModalTitle").textContent = "Add Medicine";
    form.reset();
    $("pharmMedicineId").value = "";
  }
}

function hidePharmMedicineModal() {
  const modal = $("pharmMedicineModal");
  if (modal) modal.style.display = "none";
}

async function loadPharmMedicineData(medicineId) {
  try {
    const medicines = await api("/pharmacy/medicines");
    const med = medicines.medicines.find(m => m.id === medicineId);
    if (!med) return;
    
    $("pharmMedicineId").value = med.id;
    $("pharmMedicineName").value = med.name || "";
    $("pharmMedicineGeneric").value = med.genericName || "";
    $("pharmMedicineManufacturer").value = med.manufacturer || "";
    $("pharmMedicineCategorySelect").value = med.category || "";
    $("pharmMedicineDosageForms").value = Array.isArray(med.dosageForms) ? med.dosageForms.join(", ") : "";
    $("pharmMedicineStrengths").value = Array.isArray(med.strengths) ? med.strengths.join(", ") : "";
    $("pharmMedicineDescription").value = med.description || "";
    $("pharmMedicineStorage").value = med.storageConditions || "";
    $("pharmMedicineExpiryPeriod").value = med.expiryPeriod || "";
    $("pharmMedicineRequiresRx").checked = med.requiresPrescription !== false;
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onSavePharmMedicine(e) {
  e.preventDefault();
  try {
    const medicineId = $("pharmMedicineId").value;
    const body = {
      name: $("pharmMedicineName").value.trim(),
      genericName: $("pharmMedicineGeneric").value.trim() || null,
      manufacturer: $("pharmMedicineManufacturer").value.trim(),
      category: $("pharmMedicineCategorySelect").value,
      dosageForms: $("pharmMedicineDosageForms").value.split(",").map(s => s.trim()).filter(s => s),
      strengths: $("pharmMedicineStrengths").value.split(",").map(s => s.trim()).filter(s => s),
      description: $("pharmMedicineDescription").value.trim() || null,
      storageConditions: $("pharmMedicineStorage").value.trim() || null,
      expiryPeriod: $("pharmMedicineExpiryPeriod").value ? Number($("pharmMedicineExpiryPeriod").value) : null,
      requiresPrescription: $("pharmMedicineRequiresRx").checked,
    };
    
    if (medicineId) {
      await api(`/pharmacy/medicines/${medicineId}`, { method: "PUT", body });
      toast("Medicine updated", "success");
    } else {
      await api("/pharmacy/medicines", { method: "POST", body });
      toast("Medicine added", "success");
    }
    
    hidePharmMedicineModal();
    await onLoadPharmMedicines();
  } catch (err) {
    toast(err.message, "error");
  }
}

// Stock Management
async function onLoadPharmStock(query = "") {
  try {
    let url = "/pharmacy/stock?";
    if (query) {
      url += query;
    } else {
      const medicineId = $("pharmStockMedicine")?.value || "";
      const status = $("pharmStockStatus")?.value || "";
      if (medicineId) url += `medicineId=${encodeURIComponent(medicineId)}&`;
      if (status) url += `status=${encodeURIComponent(status)}&`;
    }
    
    const data = await api(url);
    const container = $("pharmStockList");
    if (!container) return;
    
    // Load medicines for dropdown
    await loadPharmMedicinesForStock();
    
    if (data.stock.length === 0) {
      container.innerHTML = '<div class="color-fg-muted text-small">No stock items found.</div>';
      return;
    }
    
    container.innerHTML = data.stock.map(s => {
      const statusColors = {
        available: "success",
        low_stock: "attention",
        out_of_stock: "danger",
        expired: "danger",
        quarantined: "warning"
      };
      return `
        <div class="Box p-2 mb-2">
          <div class="d-flex flex-justify-between flex-items-center">
            <div>
              <strong>${s.medicineName || "Unknown"}</strong>
              <div class="text-small">Quantity: ${s.quantity} ${s.unit} | Expiry: ${s.expiryDate}</div>
              ${s.location ? `<div class="text-small">Location: ${s.location}</div>` : ''}
              ${s.batchId ? `<div class="text-small">Batch: ${s.batchId}</div>` : ''}
            </div>
            <div class="d-flex gap-2 flex-items-center">
              <span class="Label Label--${statusColors[s.status] || 'default'}">${s.status}</span>
              <button class="btn btn-sm" onclick="editPharmStock('${s.id}')">Edit</button>
            </div>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    toast(err.message, "error");
    if ($("pharmStockList")) $("pharmStockList").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
  }
}

async function loadPharmMedicinesForStock() {
  try {
    const data = await api("/pharmacy/medicines");
    const select = $("pharmStockMedicine");
    const selectModal = $("pharmStockMedicineSelect");
    
    if (select) {
      select.innerHTML = '<option value="">All Medicines</option>';
      data.medicines.forEach(med => {
        const opt = document.createElement("option");
        opt.value = med.id;
        opt.textContent = med.name;
        select.appendChild(opt);
      });
    }
    
    if (selectModal) {
      selectModal.innerHTML = '<option value="">Select Medicine...</option>';
      data.medicines.forEach(med => {
        const opt = document.createElement("option");
        opt.value = med.id;
        opt.textContent = med.name;
        selectModal.appendChild(opt);
      });
    }
  } catch (err) {
    // Silently fail
  }
}

function showPharmStockModal(stockId = null) {
  const modal = $("pharmStockModal");
  if (!modal) return;
  
  modal.style.display = "block";
  loadPharmMedicinesForStock();
  
  if (stockId) {
    $("pharmStockModalTitle").textContent = "Edit Stock";
    loadPharmStockData(stockId);
  } else {
    $("pharmStockModalTitle").textContent = "Add Stock";
    $("pharmStockForm").reset();
    $("pharmStockId").value = "";
    $("pharmStockUnit").value = "units";
    $("pharmStockMinLevel").value = "10";
  }
}

function hidePharmStockModal() {
  const modal = $("pharmStockModal");
  if (modal) modal.style.display = "none";
}

async function loadPharmStockData(stockId) {
  try {
    const data = await api("/pharmacy/stock");
    const stock = data.stock.find(s => s.id === stockId);
    if (!stock) return;
    
    $("pharmStockId").value = stock.id;
    $("pharmStockMedicineSelect").value = stock.medicineId;
    $("pharmStockQuantity").value = stock.quantity;
    $("pharmStockUnit").value = stock.unit;
    $("pharmStockExpiryDate").value = stock.expiryDate;
    $("pharmStockLocation").value = stock.location || "";
    $("pharmStockCost").value = stock.costPerUnit || "";
    $("pharmStockPrice").value = stock.sellingPricePerUnit || "";
    $("pharmStockMinLevel").value = stock.minStockLevel || 10;
    $("pharmStockBatchId").value = stock.batchId || "";
    $("pharmStockNotes").value = stock.notes || "";
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onSavePharmStock(e) {
  e.preventDefault();
  try {
    const stockId = $("pharmStockId").value;
    const body = {
      medicineId: $("pharmStockMedicineSelect").value,
      quantity: Number($("pharmStockQuantity").value),
      unit: $("pharmStockUnit").value || "units",
      expiryDate: $("pharmStockExpiryDate").value,
      location: $("pharmStockLocation").value.trim() || null,
      costPerUnit: $("pharmStockCost").value ? Number($("pharmStockCost").value) : null,
      sellingPricePerUnit: $("pharmStockPrice").value ? Number($("pharmStockPrice").value) : null,
      minStockLevel: Number($("pharmStockMinLevel").value) || 10,
      batchId: $("pharmStockBatchId").value.trim() || null,
      notes: $("pharmStockNotes").value.trim() || null,
    };
    
    if (stockId) {
      await api(`/pharmacy/stock/${stockId}`, { method: "PUT", body });
      toast("Stock updated", "success");
    } else {
      await api("/pharmacy/stock", { method: "POST", body });
      toast("Stock added", "success");
    }
    
    hidePharmStockModal();
    await onLoadPharmStock();
  } catch (err) {
    toast(err.message, "error");
  }
}

// Quality Verification
async function onLoadPharmQuality() {
  try {
    const data = await api("/pharmacy/quality-verifications");
    const container = $("pharmQualityList");
    if (!container) return;
    
    if (data.verifications.length === 0) {
      container.innerHTML = '<div class="color-fg-muted text-small">No quality verifications found.</div>';
      return;
    }
    
    container.innerHTML = data.verifications.map(v => {
      const statusColors = {
        approved: "success",
        rejected: "danger",
        pending: "default",
        quarantined: "warning"
      };
      return `
        <div class="Box p-2 mb-2">
          <div class="d-flex flex-justify-between flex-items-center">
            <div>
              <strong>Medicine ID: ${v.medicineId}</strong>
              <div class="text-small">Standard: ${v.standard} | Date: ${v.verificationDate}</div>
              <div class="text-small">Checks: ${Object.entries(v.checks).filter(([k, val]) => val === "pass").length} passed, ${Object.entries(v.checks).filter(([k, val]) => val === "fail").length} failed</div>
            </div>
            <span class="Label Label--${statusColors[v.overallStatus] || 'default'}">${v.overallStatus}</span>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    toast(err.message, "error");
    if ($("pharmQualityList")) $("pharmQualityList").innerHTML = `<div class="flash flash-error">Error: ${err.message}</div>`;
  }
}

function showPharmQualityModal() {
  const modal = $("pharmQualityModal");
  if (!modal) return;
  
  modal.style.display = "block";
  loadPharmMedicinesForQuality();
  $("pharmQualityForm").reset();
}

function hidePharmQualityModal() {
  const modal = $("pharmQualityModal");
  if (modal) modal.style.display = "none";
}

async function loadPharmMedicinesForQuality() {
  try {
    const data = await api("/pharmacy/medicines");
    const select = $("pharmQualityMedicine");
    if (!select) return;
    
    select.innerHTML = '<option value="">Select Medicine...</option>';
    data.medicines.forEach(med => {
      const opt = document.createElement("option");
      opt.value = med.id;
      opt.textContent = med.name;
      select.appendChild(opt);
    });
  } catch (err) {
    // Silently fail
  }
}

async function onSavePharmQuality(e) {
  e.preventDefault();
  try {
    const body = {
      medicineId: $("pharmQualityMedicine").value,
      batchId: $("pharmQualityBatchId").value.trim() || null,
      stockId: $("pharmQualityStockId").value.trim() || null,
      standard: $("pharmQualityStandard").value,
      checks: {
        appearance: $("pharmQualityAppearance").value,
        packaging: $("pharmQualityPackaging").value,
        labeling: $("pharmQualityLabeling").value,
        temperature: $("pharmQualityTemperature").value,
        expiry: $("pharmQualityExpiry").value,
        batchCertificate: $("pharmQualityBatchCert").value,
        tamperEvidence: $("pharmQualityTamper").value,
      },
      notes: $("pharmQualityNotes").value.trim() || null,
    };
    
    await api("/pharmacy/quality-verification", { method: "POST", body });
    toast("Quality verification saved", "success");
    
    hidePharmQualityModal();
    await onLoadPharmQuality();
  } catch (err) {
    toast(err.message, "error");
  }
}

// Global functions for onclick handlers
window.editPharmMedicine = (id) => showPharmMedicineModal(id);
window.editPharmStock = (id) => showPharmStockModal(id);

// Debounce helper
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Check if user should be redirected based on URL
async function checkUrlRole() {
  const currentPath = window.location.pathname;
  const rolePaths = {
    "/doctor": "doctor",
    "/pharmacy": "pharmacy",
    "/patient": "patient",
    "/manufacturer": "manufacturer",
    "/admin": "admin"
  };
  
  const expectedRole = rolePaths[currentPath];
  const token = getToken();
  
  if (expectedRole && token) {
    // User is logged in and on a role-specific path
    // Verify they have the correct role
    try {
      const whoami = await api("/demo/whoami");
      if (whoami.auth.role !== expectedRole) {
        // Wrong role, redirect to their role path
        const rolePaths = {
          doctor: "/doctor",
          pharmacy: "/pharmacy",
          patient: "/patient",
          manufacturer: "/manufacturer",
          admin: "/admin"
        };
        window.location.href = rolePaths[whoami.auth.role] || "/";
      }
    } catch (err) {
      // Token invalid, will be handled by updateAuthUi
    }
  }
}

async function init() {
  wire();
  setAccessTab("login");
  await checkHealth();
  await checkUrlRole();
  await updateAuthUi();

  const pharmLink = document.querySelector('a[href="/pharmacist/signup"]');
  if (pharmLink) pharmLink.href = `${computeApiOrigin()}/pharmacist/signup`;

  // Initialize toggle button labels (in case server-side render differs).
  $("auditToggleJsonBtn").textContent = $("audit_out").hidden ? "Show JSON" : "Hide JSON";
  $("adminUserAuditToggleJsonBtn").textContent = $("adminUserAuditOut").hidden ? "Show JSON" : "Hide JSON";

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
