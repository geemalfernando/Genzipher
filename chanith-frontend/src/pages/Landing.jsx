import { Link } from 'react-router-dom'
import '../styles/Landing.css'

export default function Landing() {
  return (
    <div className="landing-container">
      <header className="landing-header">
        <div className="landing-logo">
          <div className="medical-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <span>CARECRYPT</span>
        </div>
        <nav className="landing-nav">
          <a href="#features">Features</a>
          <a href="#solutions">Solutions</a>
          <a href="#security">Security</a>
          <Link to="/login" className="nav-link">Login</Link>
          <Link to="/signup" className="btn btn-primary">Get Started</Link>
        </nav>
      </header>

      <section className="landing-hero">
        <div className="hero-content">
          <div className="hero-text">
            <div className="hero-badge">
              <span>Enterprise Healthcare Security Platform</span>
            </div>
            <h1>Secure Healthcare Trust Platform</h1>
            <p className="hero-subtitle">
              Advanced security infrastructure for healthcare organizations. Protect patient data, 
              secure prescriptions, and ensure medication integrity with enterprise-grade encryption 
              and biometric authentication.
            </p>

            <div className="hero-cta-section">
              <div className="hero-cta-buttons">
                <Link to="/login" className="btn-primary-large">
                  <span>Sign In</span>
                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M7.5 15L12.5 10L7.5 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </Link>
                <Link to="/signup" className="btn-outline-large">
                  <span>Sign Up</span>
                </Link>
              </div>
            </div>

            <div className="hero-trust-indicators">
              <div className="trust-item">
                <div className="trust-icon">
                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M10 18C14.4183 18 18 14.4183 18 10C18 5.58172 14.4183 2 10 2C5.58172 2 2 5.58172 2 10C2 14.4183 5.58172 18 10 18Z" stroke="currentColor" strokeWidth="2"/>
                    <path d="M7 10L9 12L13 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <span>HIPAA Compliant</span>
              </div>
              <div className="trust-item">
                <div className="trust-icon">
                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M10 2L12.09 7.26L18 8.27L14 12.14L15.18 18.02L10 15.77L4.82 18.02L6 12.14L2 8.27L7.91 7.26L10 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <span>Enterprise Grade</span>
              </div>
              <div className="trust-item">
                <div className="trust-icon">
                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M10 18C14.4183 18 18 14.4183 18 10C18 5.58172 14.4183 2 10 2C5.58172 2 2 5.58172 2 10C2 14.4183 5.58172 18 10 18Z" stroke="currentColor" strokeWidth="2"/>
                    <path d="M10 6V10L12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                </div>
                <span>24/7 Support</span>
              </div>
            </div>
          </div>
          <div className="hero-image">
            <div className="hero-illustration">
              <div className="hero-visual-container">
                <div className="hero-icon-large">
                  <svg width="120" height="120" viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="60" cy="60" r="55" stroke="rgba(255,255,255,0.3)" strokeWidth="2"/>
                    <path d="M60 30L45 45H55V75H65V45H75L60 30Z" fill="rgba(255,255,255,0.4)"/>
                    <path d="M40 80H80V90H40V80Z" fill="rgba(255,255,255,0.4)"/>
                    <path d="M50 90H70V100H50V90Z" fill="rgba(255,255,255,0.4)"/>
                  </svg>
                </div>
                <div className="hero-illustration-content">
                  <h3>Secure Healthcare Management</h3>
                  <p>Trusted by healthcare professionals worldwide</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="features" className="features-section">
        <div className="features-container">
          <div className="section-header">
            <h2 className="section-title">Enterprise Security Features</h2>
            <p className="section-subtitle">
              Comprehensive security infrastructure designed for healthcare organizations
            </p>
          </div>
          <div className="features-grid">
            <div className="healthcare-card feature-card">
              <div className="feature-icon-wrapper">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 8V12L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <h3>Identity Protection</h3>
              <p>Multi-factor authentication and biometric verification prevent unauthorized access. Advanced device fingerprinting and session management ensure secure access control.</p>
            </div>
            <div className="healthcare-card feature-card">
              <div className="feature-icon-wrapper">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <h3>Prescription Security</h3>
              <p>Digital signature verification and tamper-proof prescription system. Cryptographic integrity checks ensure medication authenticity and prevent unauthorized modifications.</p>
            </div>
            <div className="healthcare-card feature-card">
              <div className="feature-icon-wrapper">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <rect x="3" y="8" width="18" height="12" rx="2" stroke="currentColor" strokeWidth="2"/>
                  <path d="M3 10C3 8.89543 3.89543 8 5 8H19C20.1046 8 21 8.89543 21 10V18C21 19.1046 20.1046 20 19 20H5C3.89543 20 3 19.1046 3 18V10Z" stroke="currentColor" strokeWidth="2"/>
                  <path d="M7 8V6C7 4.34315 8.34315 3 10 3H14C15.6569 3 17 4.34315 17 6V8" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <h3>Data Encryption</h3>
              <p>AES-256-GCM encryption for patient vital signs and health data. Per-patient key management ensures data confidentiality and compliance with healthcare regulations.</p>
            </div>
            <div className="healthcare-card feature-card">
              <div className="feature-icon-wrapper">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <h3>Quality Assurance</h3>
              <p>Batch verification and provenance tracking prevent medication substitution. Real-time quality checks ensure medication integrity throughout the supply chain.</p>
            </div>
            <div className="healthcare-card feature-card">
              <div className="feature-icon-wrapper">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 6V12L16 14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <h3>Fraud Detection</h3>
              <p>Real-time anomaly detection and behavioral analysis. Automated threat response and comprehensive fraud event tracking for proactive security management.</p>
            </div>
            <div className="healthcare-card feature-card">
              <div className="feature-icon-wrapper">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M16 13H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  <path d="M16 17H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  <path d="M10 9H9H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <h3>Audit Trail</h3>
              <p>Tamper-evident audit logs with cryptographic hash chains. Complete activity tracking and compliance reporting for regulatory requirements and forensic analysis.</p>
            </div>
          </div>
        </div>
      </section>

      <section id="security" className="security-section">
        <div className="security-container">
          <div className="security-content">
            <div className="security-text">
              <h2>Enterprise-Grade Security Infrastructure</h2>
              <p>
                GenZipher Healthcare provides comprehensive security solutions designed for 
                healthcare organizations. Our platform combines advanced encryption, biometric 
                authentication, and real-time fraud detection to protect patient data and ensure 
                medication integrity.
              </p>
              <div className="security-metrics">
                <div className="metric-item">
                  <div className="metric-value">10,000+</div>
                  <div className="metric-label">Healthcare Professionals</div>
                </div>
                <div className="metric-item">
                  <div className="metric-value">99.9%</div>
                  <div className="metric-label">System Uptime</div>
                </div>
                <div className="metric-item">
                  <div className="metric-value">100%</div>
                  <div className="metric-label">HIPAA Compliance</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="footer-content">
          <div className="footer-main">
            <div className="footer-brand">
              <div className="footer-logo">
                <div className="medical-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <span>GenZipher Healthcare</span>
              </div>
              <p className="footer-tagline">
                Enterprise healthcare security platform for modern healthcare organizations.
              </p>
            </div>
            <div className="footer-links">
              <div className="footer-column">
                <h4>Platform</h4>
                <a href="#features">Features</a>
                <a href="#security">Security</a>
                <Link to="/login">Login</Link>
              </div>
              <div className="footer-column">
                <h4>Resources</h4>
                <a href="#solutions">Solutions</a>
                <a href="#about">About</a>
                <Link to="/signup">Get Started</Link>
              </div>
            </div>
          </div>
          <div className="footer-bottom">
            <p>&copy; 2024 GenZipher Healthcare. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
