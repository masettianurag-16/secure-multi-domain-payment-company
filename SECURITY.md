# Security Policy & Controls Specification

## Secure Multi-Domain Payment Company

This document outlines the security controls, threat mitigation strategies, and design decisions implemented in this academic prototype.

---

## 1. Threat Model & Asset Identification

### Critical Assets to Protect
1. **User Credentials:** User authentication data (passwords, session cookies).
2. **Customer Identity & Data:** Email addresses, profile info, and transaction records.
3. **Administrative Authority:** Privilege to inspect system logs and user directories.
4. **Audit Integrity:** Tamper-evident logging of security incidents and transactions.

### Potential Threats & Mitigations

| Threat | Risk Level | Mitigation in Prototype |
|---|---|---|
| **Credential Theft / Database Dump** | High | Passwords hashed using salted Scrypt via `werkzeug.security`. Even if the SQLite file is stolen, passwords cannot be reversed. |
| **Privilege Escalation** | High | Role-Based Access Control (RBAC) enforced server-side with `@role_required("ADMIN")`. Role state is verified per request from signed session. |
| **SQL Injection (SQLi)** | Critical | 100% of database interactions use SQLite prepared statements with parameter substitution (`?`). String formatting/concatenation is strictly forbidden. |
| **Cross-Site Scripting (XSS)** | High | Jinja2 auto-escaping is active across all HTML templates. Session cookies are protected with `HttpOnly = True` to prevent JavaScript theft. |
| **Cross-Site Request Forgery (CSRF)** | Medium | Session cookies use `SameSite = 'Lax'` preventing third-party websites from dispatching unauthorized state-changing cross-origin requests. |
| **Payment Card Data Leakage** | Critical | Raw card numbers and CVVs are discarded immediately after in-memory regex validation. Only the last 4 digits are retained for customer reference. |
| **Session Fixation** | Medium | `session.clear()` is called prior to authentication, issuing a clean session context upon successful login. |
| **Information Disclosure via Errors** | Medium | Custom 404 and 500 error handlers intercept uncaught exceptions and return generic error pages, preventing server stack trace leaks. |

---

## 2. OWASP Top 10 (2021) Mapping

| OWASP Risk Category | Status in Prototype | Implementation Reference |
|---|---|---|
| **A01: Broken Access Control** | **Protected** | RBAC decorators (`@role_required`, `@login_required`) enforce boundaries between `CUSTOMER` and `ADMIN`. Unauthorized attempts are blocked and logged. |
| **A02: Cryptographic Failures** | **Protected** | Modern key derivation (Scrypt) with automatic salt. No plaintext credentials. Pre-configured TLS cookie flags (`SESSION_COOKIE_SECURE`). |
| **A03: Injection** | **Protected** | Parameterized queries prevent SQL injection. Strict regex input validation rejects malformed strings. |
| **A04: Insecure Design** | **Protected** | Multi-domain isolation ensures that public marketing pages, customer dashboards, checkout flows, and admin portals are logically partitioned. |
| **A05: Security Misconfiguration** | **Protected** | Explicit cookie security policies (`HttpOnly`, `SameSite=Lax`). Debug mode toggle documented for production hardening. |
| **A06: Vulnerable and Outdated Components** | **Protected** | Uses minimal, current dependencies: Python 3.13 standard library (`sqlite3`, `secrets`), Flask 3.1.3, and Werkzeug 3.1.8. |
| **A07: Identification and Authentication Failures** | **Protected** | Password complexity rules enforced (&ge; 8 characters, letters + digits). Protection against brute-force visibility through generic error responses. |
| **A08: Software and Data Integrity Failures** | **Protected** | Zero untrusted deserialization. SQLite database transactions ensure ACID data consistency. |
| **A09: Security Logging and Monitoring Failures** | **Protected** | `security_logs` records successes, failures, and blocked access attempts with IP address and timestamps. Filterable admin view. |
| **A10: Server-Side Request Forgery (SSRF)** | **N/A** | Prototype contains no external URL fetching or outbound HTTP request handlers. |

---

## 3. Data Protection: Payment Security Architecture

Real payment processors must adhere to the **Payment Card Industry Data Security Standard (PCI-DSS)**. This prototype demonstrates adherence to PCI-DSS core philosophies within an educational sandbox:

```
[ User Payment Input Form ]
  ├── Amount ($)
  ├── Cardholder Name
  ├── Demo Card Number (16 Digits)
  ├── Expiration (MM/YY)
  └── Demo CVV (3-4 Digits)
            │
            ▼
[ In-Memory Input Validation (security.py) ]
  ├── Check Amount > 0.00 and <= 10000.00
  ├── Check Card matches 16-digit test regex
  └── Check CVV matches 3-4 digit regex
            │
            ├───► CVV and Raw Card Dropped from Memory (PURGED)
            │
            ▼
[ Sanitized Record Saved to SQLite ]
  ├── transaction_id: "TXN-A1B2C3D4E5F6"
  ├── user_id: 2
  ├── amount: 49.99
  ├── demo_card_last4: "1111"
  └── status: "SUCCESS"
```

---

## 4. Security Audit Logging Policy

Audit logs in `security_logs` provide non-repudiation and visibility:

* **What IS Logged:**
  * Authentication successes (`LOGIN_SUCCESS`)
  * Authentication failures (`LOGIN_FAILURE`)
  * Account registrations (`REGISTRATION_SUCCESS`)
  * Logout actions (`LOGOUT`)
  * Privilege escalation attempts (`PRIVILEGE_VIOLATION`)
  * Unauthenticated route accesses (`UNAUTHORIZED_ACCESS`)
  * Payment simulation results (`DEMO_PAYMENT_SUCCESS`, `DEMO_PAYMENT_FAILED`)
  * Administrative access events (`ADMIN_ACTION`)

* **What is NEVER Logged:**
  * Passwords (neither plaintext nor hashes)
  * Credit card Primary Account Numbers (PAN)
  * Card Verification Values (CVV)
  * Personal cryptographic salts or session tokens

---

## 5. Prototype vs Production Deployment Comparison

| Security Dimension | This Academic Prototype | Production Recommendation |
|---|---|---|
| **Transport Encryption** | HTTP (localhost testing) | HTTPS with TLS 1.3 certificate (Let's Encrypt / Cloudflare). |
| **Cookie Flags** | `SESSION_COOKIE_SECURE = False` | Set `SESSION_COOKIE_SECURE = True` in `app.py`. |
| **Database** | File-based SQLite | PostgreSQL / MySQL with connection encryption & replication. |
| **Payment Processing** | Sanitized in-memory simulation | Delegated PCI-compliant gateway (Stripe Elements, Braintree tokenization). |
| **Multi-Factor Auth** | Single-factor password | TOTP / WebAuthn hardware token requirement for Admin role. |
| **Rate Limiting** | Flask basic handlers | Reverse-proxy rate limiting (e.g. Nginx `limit_req` or Cloudflare WAF). |
