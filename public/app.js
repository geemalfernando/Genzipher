const API_BASE = "";

function $(id) {
  return document.getElementById(id);
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
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

function getToken() {
  return localStorage.getItem("gz_token");
}

function setToken(token) {
  if (!token) localStorage.removeItem("gz_token");
  else localStorage.setItem("gz_token", token);
  updateAuthUi();
}

async function api(path, { method = "GET", body } = {}) {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
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

    if (auth.role === "patient") {
      await refreshPatientProfile();
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
    const username = $("login_username").value.trim();
    const password = $("login_password").value;
    const mfaCode = $("login_mfa").value.trim() || undefined;
    const out = await api("/auth/login", { method: "POST", body: { username, password, mfaCode } });
    setToken(out.token);
    toast("Logged in", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

function onLogout() {
  setToken(null);
  toast("Logged out", "success");
}

async function onPreRegister(e) {
  e.preventDefault();
  try {
    const body = {
      username: $("pr_username").value.trim(),
      password: $("pr_password").value,
      geo: $("pr_geo").value.trim() || undefined,
      deviceId: $("pr_deviceId").value.trim() || undefined,
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
      code: $("vc_code").value.trim(),
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
    $("audit_out").value = pretty({
      count: result.count,
      chainSanity: sanity,
      entries: result.entries,
    });
    toast(sanity.ok ? "Audit loaded (chain links consistent)" : "Audit loaded (chain mismatch!)", sanity.ok ? "success" : "error");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function onIssueClinicCode(e) {
  e.preventDefault();
  try {
    const patientId = $("cc_patientId").value.trim();
    const expiresMinutes = Number($("cc_expires").value);
    const out = await api("/clinic/codes", {
      method: "POST",
      body: {
        patientId: patientId || undefined,
        expiresMinutes: Number.isFinite(expiresMinutes) ? expiresMinutes : 10,
      },
    });
    $("cc_code").textContent = out.code || "—";
    $("cc_expiry").textContent = out.expiresAt || "—";
    toast("Clinic code generated", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function refreshPatientProfile() {
  try {
    const out = await api("/patients/me/profile");
    $("patient_profile_out").value = pretty(out);
    $("patient_token").textContent = out.patientToken || "—";
    $("patient_did").textContent = out.profile?.did || "—";
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

function wire() {
  $("tabLogin").addEventListener("click", () => setAccessTab("login"));
  $("tabRegister").addEventListener("click", () => setAccessTab("register"));

  $("loginForm").addEventListener("submit", onLogin);
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
  $("auditLoadBtn").addEventListener("click", onLoadAudit);
  $("clinicCodeForm").addEventListener("submit", onIssueClinicCode);
  $("cc_copy").addEventListener("click", async () => {
    const code = $("cc_code").textContent || "";
    await navigator.clipboard.writeText(code);
    toast("Copied clinic code", "success");
  });

  $("patientRefreshBtn").addEventListener("click", refreshPatientProfile);
  $("patientIssueDidBtn").addEventListener("click", onPatientIssueDid);
  $("patientProvisionKeyBtn").addEventListener("click", onPatientProvisionKey);
  $("bindDeviceForm").addEventListener("submit", onBindDevice);
  $("verifyDeviceForm").addEventListener("submit", onVerifyDevice);

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
  await updateAuthUi();

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
