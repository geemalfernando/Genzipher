import React from "react";
import { Link, Route, Routes } from "react-router-dom";
import Landing from "./pages/Landing.jsx";
import Login from "./pages/Login.jsx";
import Pharmacy from "./pages/Pharmacy.jsx";
import PharmacistSignup from "./pages/PharmacistSignup.jsx";

export default function App() {
  return (
    <div className="container-xl p-3 p-md-4">
      <header className="Box p-3 mb-3 gz-hero">
        <div className="d-flex flex-justify-between flex-items-center flex-wrap gap-2">
          <div>
            <div className="d-flex flex-items-center gap-2">
              <span className="Label Label--success">MVP</span>
              <h1 className="f3 mb-0">GenZipher Healthcare Trust Platform</h1>
            </div>
            <p className="color-fg-muted mt-1 mb-0">
              Identity trust • Vitals privacy • Prescription integrity • Supply-chain verification
            </p>
          </div>
          <nav className="d-flex gap-2 flex-wrap">
            <Link className="btn btn-sm" to="/">
              Home
            </Link>
            <Link className="btn btn-sm" to="/login">
              Login
            </Link>
            <Link className="btn btn-sm" to="/pharmacist/signup">
              Pharmacist signup
            </Link>
            <Link className="btn btn-sm" to="/pharmacy">
              Pharmacy
            </Link>
          </nav>
        </div>
      </header>

      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/pharmacist/signup" element={<PharmacistSignup />} />
        <Route path="/pharmacy" element={<Pharmacy />} />
        <Route path="*" element={<Landing notFound />} />
      </Routes>
    </div>
  );
}

