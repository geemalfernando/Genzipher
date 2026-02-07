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

async function updateAuthUi() {
  const token = getToken();
  $("logoutBtn").hidden = !token;
  $("loginBox").hidden = Boolean(token);
  $("appBox").hidden = !token;

  if (!token) {
    $("whoami").textContent = "Not logged in";
    showRole("doctor");
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

function wire() {
  $("loginForm").addEventListener("submit", onLogin);
  $("logoutBtn").addEventListener("click", onLogout);

  $("rxForm").addEventListener("submit", onCreateRx);
  $("rxVerifyBtn").addEventListener("click", onVerifyRx);
  $("rxTamperBtn").addEventListener("click", onTamperRx);

  $("batchForm").addEventListener("submit", onCreateBatch);
  $("batchVerifyBtn").addEventListener("click", onVerifyBatch);
  $("batchTamperBtn").addEventListener("click", onTamperBatch);

  $("dispenseForm").addEventListener("submit", onDispense);
  $("auditLoadBtn").addEventListener("click", onLoadAudit);

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
