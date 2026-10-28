"""
app.py - Main Flask Application for Secure Multi-Domain Payment Company.
Demonstrates 5 logical sections/domains:
  1. Main Website (/)
  2. Customer Portal (/customer)
  3. Payment Application (/payment)
  4. Admin Portal (/admin)
  5. REST API (/api)
"""

import os
import uuid
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from database import get_db_connection, init_db
from security import (
    hash_password,
    verify_password,
    validate_registration_input,
    validate_payment_input,
    log_security_event,
    login_required,
    role_required
)

app = Flask(__name__)

# Security: In production, generate a high-entropy secret key from environment variables.
# For local college demonstration, we use a fixed or secrets-generated key.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "secure-multi-domain-college-demo-secret-key-2026")

# Cookie Security Settings:
# - HttpOnly: Prevents client-side JavaScript from accessing session cookies (mitigates XSS cookie theft).
# - SameSite=Lax: Protects against Cross-Site Request Forgery (CSRF).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # Note on Secure Communication:
    # In production with TLS/HTTPS, set SESSION_COOKIE_SECURE=True.
    # For local HTTP demonstration, SESSION_COOKIE_SECURE remains False to allow local testing.
    SESSION_COOKIE_SECURE=False
)

# Context processor to pass active user information and domain info to all templates
@app.context_processor
def inject_global_template_data():
    current_role = session.get("role")
    current_username = session.get("username")
    return {
        "is_authenticated": "user_id" in session,
        "current_username": current_username,
        "current_role": current_role,
        "current_year": datetime.now().year,
        "active_path": request.path
    }


# ==============================================================================
# SECTION 1: MAIN WEBSITE (Public Domain: /)
# ==============================================================================

@app.route("/")
def home():
    """Main Website Landing Page - Highlights multi-domain architecture and security features."""
    return render_template("home.html")

@app.route("/about")
def about():
    """About Page - Describes prototype objectives, security architecture, and limitations."""
    return render_template("about.html")

@app.route("/security-info")
def security_info():
    """Security Information Page - Interactive overview of all security controls."""
    return render_template("security_info.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Customer Login Route."""
    # If already logged in as customer, redirect to customer dashboard
    if "user_id" in session and session.get("role") == "CUSTOMER":
        return redirect(url_for("customer_dashboard"))
    if "user_id" in session and session.get("role") == "ADMIN":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("login.html")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?;",
            (identifier, identifier)
        ).fetchone()
        conn.close()

        if user and verify_password(password, user["password_hash"]):
            # Authentication successful
            session.clear()  # Prevent session fixation attacks
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["role"] = user["role"]

            log_security_event(user["id"], f"LOGIN_SUCCESS: User '{user['username']}' logged in.", "SUCCESS")
            flash(f"Welcome back, {user['username']}! Logged in successfully.", "success")

            # Route according to role
            if user["role"] == "ADMIN":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("customer_dashboard"))
        else:
            # Authentication failure
            log_security_event(
                None,
                f"LOGIN_FAILURE: Failed login attempt for identifier '{identifier}'.",
                "FAILURE"
            )
            flash("Invalid credentials. Please verify your username/email and password.", "danger")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Customer Self-Registration Route."""
    if "user_id" in session:
        return redirect(url_for("customer_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Input Validation
        is_valid, error_msg = validate_registration_input(username, email, password)
        if not is_valid:
            flash(error_msg, "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter your password.", "danger")
            return render_template("register.html", username=username, email=email)

        # 2. Check for unique username and email
        conn = get_db_connection()
        existing = conn.execute(
            "SELECT username, email FROM users WHERE username = ? OR email = ?;",
            (username, email)
        ).fetchone()

        if existing:
            conn.close()
            flash("Username or Email already registered. Please choose another or log in.", "warning")
            return render_template("register.html", username=username, email=email)

        # 3. Securely hash password and store
        pwd_hash = hash_password(password)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, 'CUSTOMER');
            """, (username, email, pwd_hash))
            new_user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            log_security_event(new_user_id, f"REGISTRATION_SUCCESS: New customer registered '{username}'.", "SUCCESS")
            flash("Account registered successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            conn.close()
            flash("An error occurred during registration. Please try again.", "danger")

    return render_template("register.html")

@app.route("/logout")
def logout():
    """Secure Logout Route - Invalidates the active session."""
    user_id = session.get("user_id")
    username = session.get("username")
    if user_id:
        log_security_event(user_id, f"LOGOUT: User '{username}' logged out.", "SUCCESS")
    session.clear()
    flash("You have been safely logged out.", "info")
    return redirect(url_for("login"))


# ==============================================================================
# SECTION 2: CUSTOMER PORTAL (Domain: /customer)
# ==============================================================================

@app.route("/customer/dashboard")
@login_required
def customer_dashboard():
    """Customer Dashboard - Overview of customer account and recent demo activity."""
    conn = get_db_connection()
    user_id = session["user_id"]
    
    # Fetch recent transactions
    transactions = conn.execute("""
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5;
    """, (user_id,)).fetchall()

    # Calculate summary metrics
    total_spent = conn.execute("""
        SELECT COALESCE(SUM(amount), 0.0) as total FROM transactions
        WHERE user_id = ? AND status = 'SUCCESS';
    """, (user_id,)).fetchone()["total"]

    tx_count = conn.execute("""
        SELECT COUNT(*) as count FROM transactions
        WHERE user_id = ?;
    """, (user_id,)).fetchone()["count"]

    conn.close()

    return render_template(
        "customer_dashboard.html",
        transactions=transactions,
        total_spent=total_spent,
        tx_count=tx_count
    )

@app.route("/customer/profile")
@login_required
def customer_profile():
    """Customer Profile - View account details with sensitive password masked."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?;", (session["user_id"],)).fetchone()
    conn.close()

    # Display only a safe snippet of the hash algorithm to demonstrate hashing without exposing full hash
    safe_hash_preview = user["password_hash"][:25] + "... [Cryptographically Protected]"

    return render_template("customer_profile.html", user=user, hash_preview=safe_hash_preview)

@app.route("/customer/transactions")
@login_required
def customer_transactions():
    """Customer Transaction History."""
    conn = get_db_connection()
    transactions = conn.execute("""
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY created_at DESC;
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template("customer_transactions.html", transactions=transactions)


# ==============================================================================
# SECTION 3: PAYMENT APPLICATION (Domain: /payment)
# ==============================================================================

@app.route("/payment")
@login_required
def payment_form():
    """Payment Application Checkout Simulator Form."""
    # Pre-generate a unique demo transaction reference token
    demo_ref = f"REF-{secrets.token_hex(4).upper()}"
    return render_template("payment.html", demo_ref=demo_ref)

@app.route("/payment/process", methods=["POST"])
@login_required
def payment_process():
    """
    Process Demo Payment Simulation.
    Demonstrates:
      - Rigorous input validation
      - Safe handling: Card number masked to last 4 digits
      - CVV and raw card number are immediately discarded and NEVER saved
      - Audit log generation
    """
    amount = request.form.get("amount", "").strip()
    card_number = request.form.get("card_number", "").strip()
    exp_date = request.form.get("exp_date", "").strip()
    cvv = request.form.get("cvv", "").strip()
    note = request.form.get("note", "Demo Payment").strip()

    user_id = session["user_id"]

    # 1. Validation
    is_valid, error_msg = validate_payment_input(amount, card_number, exp_date, cvv)
    if not is_valid:
        log_security_event(user_id, f"PAYMENT_VALIDATION_FAILURE: {error_msg}", "FAILURE")
        flash(f"Payment Rejected: {error_msg}", "danger")
        return redirect(url_for("payment_form"))

    # 2. Extract safe metadata only
    clean_card = card_number.replace(" ", "").replace("-", "")
    card_last4 = clean_card[-4:]
    float_amount = round(float(amount), 2)
    tx_id = f"TXN-{secrets.token_hex(6).upper()}"

    # 3. Simulate Gateway Response (Reject cards starting with 9999 as a demo failure case)
    if clean_card.startswith("9999"):
        status = "FAILED"
        log_security_event(user_id, f"DEMO_PAYMENT_FAILED: Card declined for ${float_amount} (Tx: {tx_id})", "FAILURE")
    else:
        status = "SUCCESS"
        log_security_event(user_id, f"DEMO_PAYMENT_SUCCESS: Processed ${float_amount} via Card ending in {card_last4} (Tx: {tx_id})", "SUCCESS")

    # 4. Save to Database (No CVV, No raw full card number)
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO transactions (user_id, amount, status, transaction_id, demo_card_last4)
        VALUES (?, ?, ?, ?, ?);
    """, (user_id, float_amount, status, tx_id, card_last4))
    conn.commit()
    conn.close()

    return redirect(url_for("payment_receipt", tx_id=tx_id))

@app.route("/payment/receipt/<tx_id>")
@login_required
def payment_receipt(tx_id):
    """Payment Confirmation Receipt Page."""
    conn = get_db_connection()
    tx = conn.execute(
        "SELECT * FROM transactions WHERE transaction_id = ? AND user_id = ?;",
        (tx_id, session["user_id"])
    ).fetchone()
    conn.close()

    if not tx:
        flash("Transaction receipt not found.", "warning")
        return redirect(url_for("customer_dashboard"))

    return render_template("receipt.html", tx=tx)


# ==============================================================================
# SECTION 4: ADMIN PORTAL (Domain: /admin)
# ==============================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Dedicated Administrative Portal Login."""
    # If already logged in as admin, redirect to admin dashboard
    if "user_id" in session and session.get("role") == "ADMIN":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
        conn.close()

        if user and user["role"] == "ADMIN" and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["role"] = user["role"]

            log_security_event(user["id"], "ADMIN_LOGIN_SUCCESS: Administrator authenticated.", "SUCCESS")
            flash("Welcome to the Administrative Control Console.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            log_security_event(
                None,
                f"ADMIN_LOGIN_FAILURE: Failed administrative login attempt for '{username}'.",
                "FAILURE"
            )
            flash("Administrative authentication failed. Access denied.", "danger")

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
@role_required("ADMIN")
def admin_dashboard():
    """Admin Dashboard - System overview, metrics, and quick actions."""
    conn = get_db_connection()
    user_count = conn.execute("SELECT COUNT(*) as count FROM users;").fetchone()["count"]
    tx_count = conn.execute("SELECT COUNT(*) as count FROM transactions;").fetchone()["count"]
    total_volume = conn.execute("SELECT COALESCE(SUM(amount), 0.0) as total FROM transactions WHERE status = 'SUCCESS';").fetchone()["total"]
    security_event_count = conn.execute("SELECT COUNT(*) as count FROM security_logs;").fetchone()["count"]
    blocked_count = conn.execute("SELECT COUNT(*) as count FROM security_logs WHERE result = 'BLOCKED';").fetchone()["count"]

    recent_logs = conn.execute("""
        SELECT sl.*, u.username FROM security_logs sl
        LEFT JOIN users u ON sl.user_id = u.id
        ORDER BY sl.timestamp DESC
        LIMIT 8;
    """).fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        user_count=user_count,
        tx_count=tx_count,
        total_volume=total_volume,
        security_event_count=security_event_count,
        blocked_count=blocked_count,
        recent_logs=recent_logs
    )

@app.route("/admin/users")
@role_required("ADMIN")
def admin_users():
    """Admin View Users - View registered accounts and roles (passwords hidden)."""
    conn = get_db_connection()
    users = conn.execute("""
        SELECT id, username, email, role, created_at
        FROM users
        ORDER BY id ASC;
    """).fetchall()
    conn.close()

    log_security_event(session["user_id"], "ADMIN_ACTION: Viewed user database.", "SUCCESS")
    return render_template("admin_users.html", users=users)

@app.route("/admin/transactions")
@role_required("ADMIN")
def admin_transactions():
    """Admin View Transactions - View all demo transactions across all customers."""
    conn = get_db_connection()
    transactions = conn.execute("""
        SELECT t.*, u.username, u.email
        FROM transactions t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC;
    """).fetchall()
    conn.close()

    log_security_event(session["user_id"], "ADMIN_ACTION: Viewed global transaction logs.", "SUCCESS")
    return render_template("admin_transactions.html", transactions=transactions)

@app.route("/admin/logs")
@role_required("ADMIN")
def admin_logs():
    """Admin View Security Logs - Filterable audit log viewer."""
    filter_result = request.args.get("result", "")
    conn = get_db_connection()

    if filter_result in ['SUCCESS', 'FAILURE', 'BLOCKED']:
        logs = conn.execute("""
            SELECT sl.*, u.username FROM security_logs sl
            LEFT JOIN users u ON sl.user_id = u.id
            WHERE sl.result = ?
            ORDER BY sl.timestamp DESC;
        """, (filter_result,)).fetchall()
    else:
        logs = conn.execute("""
            SELECT sl.*, u.username FROM security_logs sl
            LEFT JOIN users u ON sl.user_id = u.id
            ORDER BY sl.timestamp DESC;
        """).fetchall()

    conn.close()
    return render_template("admin_logs.html", logs=logs, active_filter=filter_result)


# ==============================================================================
# SECTION 5: REST API (Domain: /api)
# ==============================================================================

@app.route("/api/auth/register", methods=["POST"])
def api_register():
    """API: Customer Registration."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    is_valid, error_msg = validate_registration_input(username, email, password)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg}), 400

    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?;",
        (username, email)
    ).fetchone()

    if existing:
        conn.close()
        return jsonify({"status": "error", "message": "Username or Email already registered."}), 409

    pwd_hash = hash_password(password)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, 'CUSTOMER');
    """, (username, email, pwd_hash))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_security_event(user_id, f"API_REGISTRATION: Registered '{username}'.", "SUCCESS")
    return jsonify({
        "status": "success",
        "message": "User registered successfully.",
        "user_id": user_id,
        "username": username
    }), 201

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """API: Customer and Admin Login."""
    data = request.get_json() or {}
    identifier = data.get("identifier", "").strip()
    password = data.get("password", "")

    if not identifier or not password:
        return jsonify({"status": "error", "message": "Identifier and password required."}), 400

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?;",
        (identifier, identifier)
    ).fetchone()
    conn.close()

    if user and verify_password(password, user["password_hash"]):
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user["email"]
        session["role"] = user["role"]

        log_security_event(user["id"], f"API_LOGIN_SUCCESS: '{user['username']}'.", "SUCCESS")
        return jsonify({
            "status": "success",
            "message": "Authentication successful.",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"]
            }
        }), 200
    else:
        log_security_event(None, f"API_LOGIN_FAILURE for '{identifier}'.", "FAILURE")
        return jsonify({"status": "error", "message": "Invalid credentials."}), 401

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    """API: Logout."""
    user_id = session.get("user_id")
    if user_id:
        log_security_event(user_id, "API_LOGOUT", "SUCCESS")
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."}), 200

@app.route("/api/customer/profile", methods=["GET"])
@login_required
def api_profile():
    """API: View Authenticated User Profile."""
    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, email, role, created_at FROM users WHERE id = ?;",
        (session["user_id"],)
    ).fetchone()
    conn.close()

    return jsonify({
        "status": "success",
        "profile": dict(user)
    }), 200

@app.route("/api/customer/transactions", methods=["GET"])
@login_required
def api_customer_transactions():
    """API: View Authenticated Customer's Transactions."""
    conn = get_db_connection()
    txs = conn.execute("""
        SELECT id, amount, status, transaction_id, demo_card_last4, created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY created_at DESC;
    """, (session["user_id"],)).fetchall()
    conn.close()

    return jsonify({
        "status": "success",
        "transactions": [dict(tx) for tx in txs]
    }), 200

@app.route("/api/payment/process", methods=["POST"])
@login_required
def api_payment_process():
    """API: Process Demo Payment Simulation."""
    data = request.get_json() or {}
    amount = data.get("amount", "")
    card_number = data.get("card_number", "")
    exp_date = data.get("exp_date", "")
    cvv = data.get("cvv", "")

    user_id = session["user_id"]

    is_valid, error_msg = validate_payment_input(amount, card_number, exp_date, cvv)
    if not is_valid:
        log_security_event(user_id, f"API_PAYMENT_VALIDATION_ERROR: {error_msg}", "FAILURE")
        return jsonify({"status": "error", "message": error_msg}), 400

    clean_card = str(card_number).replace(" ", "").replace("-", "")
    card_last4 = clean_card[-4:]
    float_amount = round(float(amount), 2)
    tx_id = f"TXN-{secrets.token_hex(6).upper()}"

    status = "FAILED" if clean_card.startswith("9999") else "SUCCESS"

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO transactions (user_id, amount, status, transaction_id, demo_card_last4)
        VALUES (?, ?, ?, ?, ?);
    """, (user_id, float_amount, status, tx_id, card_last4))
    conn.commit()
    conn.close()

    log_security_event(user_id, f"API_PAYMENT_{status}: Tx {tx_id}", status)

    return jsonify({
        "status": status.lower(),
        "transaction_id": tx_id,
        "amount": float_amount,
        "card_last4": card_last4,
        "message": f"Demo payment {status.lower()}."
    }), 201 if status == "SUCCESS" else 400

@app.route("/api/admin/users", methods=["GET"])
@role_required("ADMIN")
def api_admin_users():
    """API: Admin View All Users."""
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, email, role, created_at FROM users;").fetchall()
    conn.close()
    return jsonify({"status": "success", "users": [dict(u) for u in users]}), 200

@app.route("/api/admin/transactions", methods=["GET"])
@role_required("ADMIN")
def api_admin_transactions():
    """API: Admin View All Transactions."""
    conn = get_db_connection()
    txs = conn.execute("""
        SELECT t.*, u.username
        FROM transactions t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC;
    """).fetchall()
    conn.close()
    return jsonify({"status": "success", "transactions": [dict(tx) for tx in txs]}), 200

@app.route("/api/admin/logs", methods=["GET"])
@role_required("ADMIN")
def api_admin_logs():
    """API: Admin View Audit Logs."""
    conn = get_db_connection()
    logs = conn.execute("""
        SELECT sl.*, u.username FROM security_logs sl
        LEFT JOIN users u ON sl.user_id = u.id
        ORDER BY sl.timestamp DESC;
    """).fetchall()
    conn.close()
    return jsonify({"status": "success", "logs": [dict(l) for l in logs]}), 200


# ==============================================================================
# ERROR HANDLERS (Safe error reporting without leaking stack traces)
# ==============================================================================

@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "API endpoint not found."}), 404
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    log_security_event(session.get("user_id"), f"INTERNAL_ERROR on {request.path}", "FAILURE")
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500
    return render_template("500.html"), 500


# ==============================================================================
# APPLICATION ENTRYPOINT
# ==============================================================================
if __name__ == "__main__":
    init_db()
    print("=" * 65)
    print("  SECURE MULTI-DOMAIN PAYMENT COMPANY - PROTOTYPE")
    print("=" * 65)
    print("  Domains Active:")
    print("    * Main Website:        http://127.0.0.1:5000/")
    print("    * Customer Portal:     http://127.0.0.1:5000/customer/dashboard")
    print("    * Payment Gateway:     http://127.0.0.1:5000/payment")
    print("    * Admin Portal:        http://127.0.0.1:5000/admin/dashboard")
    print("    * REST API:            http://127.0.0.1:5000/api")
    print("-" * 65)
    print("  Default Demo Credentials:")
    print("    - Admin:    admin / Admin@12345")
    print("    - Customer: alice / Alice@12345")
    print("=" * 65)
    app.run(debug=True, host="127.0.0.1", port=5000)
