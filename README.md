# Secure Multi-Domain Payment Company

A college-level cybersecurity web prototype built with **Python (Flask)** and **SQLite**. This project demonstrates defense-in-depth security principles across multiple logically isolated web applications. It implements secure authentication, cryptographic password hashing, server-side Role-Based Access Control (RBAC), input sanitization, safe demo payment simulation with card masking, and security audit logging.

> **Disclaimer:** This application is strictly an **educational prototype** for academic demonstration and cybersecurity study. It is **not a real payment gateway**, does not process real currency, has no connection to banking systems, and never stores real card details or CVVs.

---

## Table of Contents
- [1. Project Overview](#1-project-overview)
- [2. Problem Statement](#2-problem-statement)
- [3. Objectives](#3-objectives)
- [4. Features Actually Implemented](#4-features-actually-implemented)
- [5. Technologies and Libraries Used](#5-technologies-and-libraries-used)
- [6. Project Folder Structure](#6-project-folder-structure)
- [7. Installation and Setup](#7-installation-and-setup)
- [8. How to Run the Project](#8-how-to-run-the-project)
- [9. How the Code Works](#9-how-the-code-works)
- [10. Screenshots](#10-screenshots)
- [11. Security Considerations and Limitations](#11-security-considerations-and-limitations)
- [12. Future Improvements](#12-future-improvements)

---

## 1. Project Overview

In software engineering and financial technology, payment platforms must protect sensitive customer data, prevent unauthorized access, and ensure complete accountability. Real-world payment systems are complex, often making it difficult for students to isolate and understand foundational security controls.

The **Secure Multi-Domain Payment Company** prototype models a financial service platform split into **5 logical application domains**:
1. **Main Website (`/`)**: Public informational portal and customer registration/login.
2. **Customer Portal (`/customer`)**: Role-gated portal for account balances, profile inspection, and personal transaction records.
3. **Payment Gateway Simulator (`/payment`)**: Checkout simulator with test card helpers, input sanitization, card masking, and confirmation receipts.
4. **Admin Portal (`/admin`)**: Restricted console for system metrics, user registry inspection, global transaction auditing, and security event logs.
5. **REST API (`/api`)**: Protected JSON endpoints enforcing authentication and role verification with standardized HTTP status codes.

---

## 2. Problem Statement

Web applications handling financial data are frequent targets of cyberattacks. Common vulnerabilities identified in the **OWASP Top 10** include:
* **Broken Access Control (A01):** Failure to enforce authorization boundaries between standard users and administrators.
* **Cryptographic Failures (A02):** Storing plain-text or weakly hashed passwords, exposing credentials during database compromise.
* **Injection Vulnerabilities (A03):** Allowing unsanitized user inputs to manipulate database queries (SQL Injection) or render malicious scripts (XSS).
* **Insecure Handling of Sensitive Financial Data:** Storing raw Primary Account Numbers (PAN) and Card Verification Values (CVV), directly violating industry security standards such as PCI-DSS.
* **Security Logging and Monitoring Failures (A09):** Neglecting audit trails or logging sensitive credentials, leaving security incidents undetectable.

This project addresses these challenges by implementing clean, transparent, and verifiable software security controls in a readable, beginner-friendly architecture.

---

## 3. Objectives

* **Demonstrate Multi-Domain Partitioning:** Structure a web application into logically separated domains with distinct route namespaces and access levels.
* **Implement Strong Authentication:** Store passwords exclusively as salted, cryptographic hashes using modern key derivation.
* **Enforce Role-Based Access Control (RBAC):** Prevent privilege escalation by restricting administrative resources to users with the `ADMIN` role.
* **Apply Strict Input Validation:** Validate and sanitize all user submissions (usernames, email addresses, transaction amounts, card formats, CVVs) on the server side.
* **Protect Payment Privacy:** Simulate payments without storing raw card numbers or CVVs, persisting only masked card metadata (`demo_card_last4`).
* **Maintain Tamper-Evident Audit Trails:** Record security events (logins, logouts, failures, privilege blocks, demo payments) while strictly excluding sensitive data from logs.
* **Provide an Automated Verification Suite:** Validate all security controls programmatically using an automated test script.

---

## 4. Features Actually Implemented

### Domain 1: Main Website (`/`)
* **Landing Page (`/`):** Architectural overview, feature cards, and direct navigation links.
* **About Page (`/about`):** Detailed breakdown of project scope, database models, and prototype boundaries.
* **Security Information (`/security-info`):** Reference guide explaining the 10 security controls implemented.
* **User Registration (`/register`):** Client and server validation with password complexity checks (&ge; 8 characters, letters, and numbers).
* **Customer Login (`/login`):** Authentication against Scrypt password hashes with session regeneration.
* **Secure Logout (`/logout`):** Destroys active session data and records the event in audit logs.

### Domain 2: Customer Portal (`/customer`)
* **Customer Dashboard (`/customer/dashboard`):** Summarizes simulated spending, transaction counts, assigned role, and recent transaction records.
* **Profile Viewer (`/customer/profile`):** Displays account ID, username, email, creation date, and a safe cryptographic hash preview (`scrypt:... [Protected]`).
* **Transaction History (`/customer/transactions`):** Tabular view of all demo payments completed by the logged-in customer.

### Domain 3: Payment Gateway Simulator (`/payment`)
* **Checkout Form (`/payment`):** Amount entry ($0.01 to $10,000.00), 16-digit test card number, expiration date, demo CVV, and memo.
* **One-Click Test Card Helpers:**
  * Success Card: `4111 1111 1111 1111` &rarr; Generates `SUCCESS` transaction.
  * Decline Simulation Card: `9999 0000 1111 2222` &rarr; Generates `FAILED` transaction.
* **Data Sanitization:** Full card number is truncated to the last 4 digits; CVV is validated in memory and dropped immediately.
* **Payment Receipt (`/payment/receipt/<tx_id>`):** Displays payment confirmation, status badge, transaction ID, timestamp, and masked card (`**** 1111`).

### Domain 4: Admin Portal (`/admin`)
* **Dedicated Admin Login (`/admin/login`):** Separate administrative login interface enforcing the `ADMIN` role.
* **Admin Dashboard (`/admin/dashboard`):** System metrics (total users, transaction count, demo payment volume, security incidents blocked) and recent audit logs.
* **User Management (`/admin/users`):** Complete user roster with usernames, emails, roles, creation dates, and masked password indicators.
* **Global Transactions (`/admin/transactions`):** Master register of all simulated payments across all users.
* **Security Event Logs (`/admin/logs`):** Searchable, filterable audit log viewer with status filters (`All`, `SUCCESS`, `FAILURE`, `BLOCKED`).

### Domain 5: REST API (`/api`)
* **Authentication Endpoints:**
  * `POST /api/auth/register` &mdash; Registers a new customer account via JSON.
  * `POST /api/auth/login` &mdash; Authenticates credentials and starts a session.
  * `POST /api/auth/logout` &mdash; Invalidates active session.
* **Customer Endpoints:**
  * `GET /api/customer/profile` &mdash; Returns authenticated profile (password hashes excluded).
  * `GET /api/customer/transactions` &mdash; Returns customer's transaction records.
* **Payment Endpoint:**
  * `POST /api/payment/process` &mdash; Validates and processes a simulated payment payload.
* **Admin Endpoints (Restricted to `ADMIN`):**
  * `GET /api/admin/users` &mdash; Returns user list (HTTP 403 if called by non-admin).
  * `GET /api/admin/transactions` &mdash; Returns all transactions.
  * `GET /api/admin/logs` &mdash; Returns complete security audit trail.

---

## 5. Technologies and Libraries Used

| Technology / Library | Version | Purpose |
|---|---|---|
| **Python** | 3.10+ (Tested on 3.13) | Core programming language |
| **Flask** | 3.1.3 | Lightweight WSGI web framework for routing and session handling |
| **Werkzeug** | 3.1.8 | Cryptographic password hashing (`generate_password_hash`, `check_password_hash`) |
| **SQLite3** | Standard Library | Zero-configuration relational database engine |
| **Jinja2** | 3.1.6 | Server-side template rendering with automatic HTML escaping |
| **re (Regular Expressions)** | Standard Library | Server-side format validation for emails, usernames, cards, and CVVs |
| **secrets & uuid** | Standard Library | Cryptographically secure token and transaction ID generation |
| **HTML5 & CSS3** | Native | Responsive, custom styling with cybersecurity-themed UI (no external CDNs needed) |

---

## 6. Project Folder Structure

```text
Secure payment/
├── app.py                      # Main Flask application (routes, session config, API, error handlers)
├── database.py                 # SQLite database layer, schema creation, connection factory, seeding
├── security.py                 # Core security logic: hashing, input validation, audit logger, RBAC decorators
├── test_prototype.py           # Automated test suite covering 20 security and functional test cases
├── secure_payment.db           # SQLite database file (auto-generated if not present)
├── README.md                   # Comprehensive project documentation
├── SECURITY.md                 # Security controls, threat modeling, and OWASP mapping
│
├── static/
│   └── css/
│       └── style.css           # Custom responsive stylesheet (cybersecurity theme, badges, cards, tables)
│
└── templates/
    ├── 404.html                # Custom 404 Not Found error page
    ├── 500.html                # Custom 500 Internal Server Error page (hides system stack traces)
    ├── about.html              # Architecture explanation, database design, prototype limitations
    ├── admin_dashboard.html    # Administrative overview with system metrics and incident counts
    ├── admin_login.html        # Dedicated administrative authentication portal
    ├── admin_logs.html         # Filterable audit log viewer (SUCCESS, FAILURE, BLOCKED)
    ├── admin_transactions.html # Master transaction register across all users
    ├── admin_users.html        # User roster displaying roles and masked credentials
    ├── base.html               # Base layout with domain indicator bar and responsive navigation
    ├── customer_dashboard.html # Customer account summary and quick payment actions
    ├── customer_profile.html   # Safe profile display with masked cryptographic hash status
    ├── customer_transactions.html # Customer's personal demo transaction history
    ├── home.html               # Main website landing page highlighting 5 logical domains
    ├── login.html              # Customer login form with input validation
    ├── payment.html            # Payment checkout simulator with test card helpers
    ├── receipt.html            # Confirmation receipt displaying masked card metadata
    ├── register.html           # Customer registration form with password policy guidance
    └── security_info.html      # Interactive breakdown of 10 security controls
```

---

## 7. Installation and Setup

### Prerequisites
* **Python 3.10 or higher** installed on your system.
* Verify Python installation by running:
  ```bash
  python --version
  ```

### Step 1: Clone or Open the Project
Navigate to the directory containing the project:
```bash
cd "c:\Users\ABHILASH\OneDrive\Documents\Secure payment"
```

### Step 2: (Optional) Create a Virtual Environment
It is good practice to isolate dependencies using a virtual environment:
```bash
python -m venv venv
```
Activate it:
* **Windows (Command Prompt):**
  ```cmd
  venv\Scripts\activate
  ```
* **Windows (PowerShell):**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
* **macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```

### Step 3: Install Required Dependencies
Install Flask and Werkzeug:
```bash
pip install Flask werkzeug
```
*(Note: `sqlite3`, `re`, `secrets`, and `datetime` are part of Python's standard library and require no separate installation).*

### Step 4: Initialize the Database
The database initializes automatically when starting `app.py`. To initialize or seed it manually at any time:
```bash
python database.py
```

---

## 8. How to Run the Project

### Start the Application Server
Run the Flask server from your terminal or command prompt:
```bash
python app.py
```

Expected terminal output:
```text
=================================================================
  SECURE MULTI-DOMAIN PAYMENT COMPANY - PROTOTYPE
=================================================================
  Domains Active:
    * Main Website:        http://127.0.0.1:5000/
    * Customer Portal:     http://127.0.0.1:5000/customer/dashboard
    * Payment Gateway:     http://127.0.0.1:5000/payment
    * Admin Portal:        http://127.0.0.1:5000/admin/dashboard
    * REST API:            http://127.0.0.1:5000/api
-----------------------------------------------------------------
  Default Demo Credentials:
    - Admin:    admin / Admin@12345
    - Customer: alice / Alice@12345
=================================================================
 * Running on http://127.0.0.1:5000
```

Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

### Pre-Seeded Demonstration Accounts

| Role | Username | Password | Purpose |
|---|---|---|---|
| **Administrator** | `admin` | `Admin@12345` | Accesses `/admin/*` and administrative APIs |
| **Customer** | `alice` | `Alice@12345` | Accesses `/customer/*` and payment simulation |

### Running the Automated Test Suite
To verify that all authentication checks, RBAC restrictions, card masking, and logging mechanisms function properly:
```bash
python test_prototype.py
```
This executes **20 automated verification tests** using Flask's test client and reports individual pass/fail results.

---

## 9. How the Code Works

### Database Architecture (`database.py`)
* **Thread-Safe Connections:** Uses `sqlite3.connect()` with `sqlite3.Row` factory to enable dictionary-like column access (`row['username']`).
* **Relational Schema:**
  * `users`: `id`, `username`, `email`, `password_hash`, `role`, `created_at`.
  * `transactions`: `id`, `user_id`, `amount`, `status`, `transaction_id`, `demo_card_last4`, `created_at`. (Notice: zero card number or CVV columns).
  * `security_logs`: `id`, `user_id`, `action`, `result`, `ip_address`, `timestamp`.
* **SQL Injection Prevention:** Every query uses parameterized placeholders (`?`). String concatenation is strictly prohibited.
* **Auto-Seeding:** On initial creation, default accounts (`admin`, `alice`) are seeded with pre-computed Scrypt hashes.

### Security Module (`security.py`)
1. **Password Hashing:**
   * `hash_password(plain_password)` uses Werkzeug's `generate_password_hash(..., method="scrypt")`.
   * `verify_password(plain_password, hashed_password)` uses constant-time comparison via `check_password_hash()` to defend against timing attacks.
2. **Server-Side Input Validation:**
   * `validate_registration_input()` verifies username format, email regex, and password complexity (&ge; 8 characters, letters + digits).
   * `validate_payment_input()` enforces positive numerical amounts ($0.01 &ndash; $10,000.00), 16-digit card patterns, MM/YY expiration dates, and 3-4 digit CVVs.
3. **Audit Logging:**
   * `log_security_event(user_id, action, result, ip_address)` writes to `security_logs`. It is architected so credentials, card numbers, and CVVs cannot be passed into logs.
4. **Access Control Decorators:**
   * `@login_required`: Checks `session["user_id"]`. Unauthenticated web requests redirect to `/login`; API requests receive HTTP 401.
   * `@role_required("ADMIN")`: Checks `session["role"]`. If a customer attempts to access an admin route, access is blocked, a `PRIVILEGE_VIOLATION` event is logged with result `BLOCKED`, and HTTP 403 (or redirect) is returned.

### Web Application & API Routing (`app.py`)
* **Session Configuration:**
  * `SESSION_COOKIE_HTTPONLY = True`: Blocks client-side JavaScript access to cookies, mitigating cookie theft via Cross-Site Scripting (XSS).
  * `SESSION_COOKIE_SAMESITE = 'Lax'`: Defends against Cross-Site Request Forgery (CSRF).
  * `session.clear()`: Called on login to protect against session fixation attacks.
* **Context Processor:** `inject_global_template_data()` passes active role, username, and path information to templates, driving dynamic domain badges.
* **Payment Pipeline:** Sanitizes amount, verifies test card, assigns a cryptographically random transaction ID (`TXN-...`), extracts `card_number[-4:]`, discards CVV, and stores the transaction in the database.
* **Error Handling:** Custom handlers for 404 and 500 status codes prevent verbose framework stack traces from leaking to users.

---

## 10. Screenshots

*Placeholders are provided below. To display actual screenshots, capture images from your running application and save them into a `screenshots/` directory.*

### 1. Main Website & Domain Navigation
<img width="1887" height="962" alt="Screenshot 2026-10-28 220837" src="https://github.com/user-attachments/assets/8ceb6a93-fbef-4576-a4bc-2928c6289ef7" />
<img width="1898" height="957" alt="Screenshot 2026-10-28 220851" src="https://github.com/user-attachments/assets/8471b02b-85d8-475f-b5a7-67a883d5a6d5" />


### 2. Customer Dashboard
<img width="1887" height="976" alt="Screenshot 2026-10-28 220935" src="https://github.com/user-attachments/assets/c6067fff-8737-456b-96d3-9f6104a9104e" />
<img width="1892" height="907" alt="Screenshot 2026-10-28 221001" src="https://github.com/user-attachments/assets/427cccd0-b16c-4d00-a52b-86a5e61090c7" />
<img width="1885" height="882" alt="Screenshot 2026-10-28 221018" src="https://github.com/user-attachments/assets/bfe9eb75-3ad5-4e23-b758-4ced9d2c6e4b" />


### 3. Payment Checkout Simulation
<img width="1872" height="890" alt="Screenshot 2026-10-28 221045" src="https://github.com/user-attachments/assets/c63a2b86-4111-43ea-aeb5-9020589eb7d7" />
<img width="1896" height="902" alt="Screenshot 2026-10-28 221106" src="https://github.com/user-attachments/assets/e49cb6ba-f190-40b9-b001-3a6f69333543" />


### 4. Sanitized Transaction Receipt
<img width="1887" height="901" alt="Screenshot 2026-10-28 221123" src="https://github.com/user-attachments/assets/3193a19a-cc5d-4a4b-92c7-a734bf81a950" />
<img width="1886" height="953" alt="Screenshot 2026-10-28 221143" src="https://github.com/user-attachments/assets/c6599d9c-cb59-4dab-be3c-efd050b40dee" />


### 5. Administrative Control Console
<img width="1882" height="896" alt="Screenshot 2026-10-28 221226" src="https://github.com/user-attachments/assets/9209a572-4588-4c3e-8411-d06d10969ca4" />
<img width="1882" height="868" alt="Screenshot 2026-10-28 221254" src="https://github.com/user-attachments/assets/388a0e72-1eb3-4796-b733-7e48083b866a" />


### 6. Security Event Audit Logs
<img width="1892" height="912" alt="Screenshot 2026-10-28 221309" src="https://github.com/user-attachments/assets/3326fc80-2fcb-4098-94ec-55af2e58410c" />
<img width="1882" height="862" alt="Screenshot 2026-10-28 221424" src="https://github.com/user-attachments/assets/25d6ebe8-a46b-4960-80a1-dd7715f2f3cc" />
<img width="1917" height="717" alt="Screenshot 2026-10-28 221438" src="https://github.com/user-attachments/assets/9b736b68-d3ad-4f99-a1da-5dae64358b09" />
<img width="1897" height="851" alt="Screenshot 2026-10-28 221456" src="https://github.com/user-attachments/assets/682f6fd6-48ca-4c08-97dc-14de05d92213" />

---

## 11. Security Considerations and Limitations

### Implemented Security Considerations
* **Defense-in-Depth:** Security is applied across multiple tiers: cookie flags, session handling, route decorators, input regex validation, and parameterized SQL queries.
* **Principle of Least Privilege:** Regular customers are restricted strictly to customer-level resources and APIs.
* **Data Minimization:** No unnecessary financial details are retained. CVVs and raw card numbers exist only momentarily in memory during validation.
* **Audit Non-Repudiation:** Key authentication and authorization actions are timestamped and tied to user IDs and IP addresses.

### Prototype Limitations
* **Simulated Transactions:** No real currency is transferred; does not integrate with Stripe, PayPal, or banking networks.
* **Local HTTP Transport:** Configured for local evaluation (`SESSION_COOKIE_SECURE = False`). A production deployment requires TLS/HTTPS certificates and `SESSION_COOKIE_SECURE = True`.
* **Single-Factor Authentication:** Relies on passwords without Multi-Factor Authentication (MFA) or OTP verification.
* **Embedded Database:** Uses local SQLite, which is ideal for single-instance demonstrations but not suited for distributed, high-concurrency production environments.

---

## 12. Future Improvements

* **Multi-Factor Authentication (MFA):** Integrate Time-Based One-Time Password (TOTP) authentication using apps like Google Authenticator for administrative accounts.
* **Rate Limiting:** Implement brute-force protection on `/login` and `/api/auth/login` using request throttling (e.g., Flask-Limiter).
* **Security Headers:** Add `Content-Security-Policy` (CSP), `X-Frame-Options`, and `Strict-Transport-Security` (HSTS) headers via Flask-Talisman.
* **Production Database Migration:** Migrate SQLite to PostgreSQL or MySQL with connection pooling and database-level encryption at rest.
* **Expanded Role Hierarchy:** Introduce additional roles such as `AUDITOR` (read-only logs access) and `SUPPORT` (customer assistance without transaction execution).
* **Automated CI/CD Security Scans:** Incorporate static application security testing (SAST) tools like Bandit and Semgrep into automated build pipelines.

---

## License & Academic Integrity

This project was developed for academic study and cybersecurity demonstration purposes. Code may be referenced, reviewed, and studied for educational coursework.
