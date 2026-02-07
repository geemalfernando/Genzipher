import React, { useState } from "react";
import { api, setToken } from "../lib/api.js";

export default function Login() {
  const [identifier, setIdentifier] = useState("doctor1");
  const [password, setPassword] = useState("password123");
  const [mfaCode, setMfaCode] = useState("");
  const [out, setOut] = useState(null);

  async function onSubmit(e) {
    e.preventDefault();
    try {
      const res = await api("/auth/login", { method: "POST", body: { identifier, password, mfaCode } });
      setOut(res);
      setToken(res.token);
    } catch (err) {
      setOut({ ok: false, error: err.message });
    }
  }

  return (
    <main className="Box p-3">
      <h2 className="f4 mb-2">Login (placeholder)</h2>
      <p className="color-fg-muted text-small mb-3">
        Replace this page with your friend’s React login UI from `dev-chanith`.
      </p>
      <form className="d-flex flex-column gap-2" onSubmit={onSubmit}>
        <label className="form-group">
          <div className="text-small color-fg-muted">Username or email</div>
          <input className="form-control input-block" value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
        </label>
        <label className="form-group">
          <div className="text-small color-fg-muted">Password</div>
          <input className="form-control input-block" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <label className="form-group">
          <div className="text-small color-fg-muted">MFA (demo for staff roles)</div>
          <input className="form-control input-block" value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="123456" />
        </label>
        <button className="btn btn-primary" type="submit">
          Login
        </button>
      </form>
      <pre className="mt-3" style={{ whiteSpace: "pre-wrap" }}>
        {out ? JSON.stringify(out, null, 2) : ""}
      </pre>
    </main>
  );
}
