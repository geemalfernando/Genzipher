import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, computeApiBase } from "../lib/api.js";

export default function Landing({ notFound = false }) {
  const [apiStatus, setApiStatus] = useState({ state: "idle", message: "" });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const base = computeApiBase();
        if (!base) {
          if (!alive) return;
          setApiStatus({ state: "warn", message: "API base not configured." });
          return;
        }
        if (!alive) return;
        setApiStatus({ state: "loading", message: "Checking API…" });
        await api("/health");
        if (!alive) return;
        setApiStatus({ state: "ok", message: `API reachable (${new URL(base).host})` });
      } catch (err) {
        if (!alive) return;
        setApiStatus({ state: "bad", message: `API not reachable: ${err.message}` });
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  return (
    <main className="Box p-3">
      {notFound ? <div className="flash flash-error mb-3">Page not found.</div> : null}

      <div
        className={`flash mb-3 ${
          apiStatus.state === "ok"
            ? "flash-success"
            : apiStatus.state === "bad"
              ? "flash-error"
              : apiStatus.state === "warn"
                ? "flash-warn"
                : "flash"
        }`}
      >
        <div className="text-small">
          <span className="Label Label--secondary mr-2">Status</span>
          {apiStatus.message || "—"}
        </div>
      </div>

      <h2 className="f4">Welcome</h2>
      <p className="color-fg-muted">
        GenZipher is a healthcare security & trust MVP that demonstrates identity hardening, device-aware step-up
        verification, prescription integrity, supply-chain verification, and tamper-evident auditing.
      </p>

      <h3 className="f5 mt-3">Get started</h3>
      <div className="d-flex gap-2 flex-wrap">
        <Link className="btn btn-primary" to="/login">
          Login
        </Link>
        <Link className="btn" to="/pharmacist/signup">
          Register pharmacist
        </Link>
        <Link className="btn" to="/pharmacy">
          Pharmacy dashboard
        </Link>
      </div>

      <h3 className="f5 mt-4">What this MVP demonstrates</h3>
      <ul className="mt-2">
        <li>Identity + step-up verification on new devices</li>
        <li>Signed prescriptions and batch certificates</li>
        <li>Pharmacy dispense gate</li>
        <li>Tamper-evident audit logging</li>
      </ul>
    </main>
  );
}
