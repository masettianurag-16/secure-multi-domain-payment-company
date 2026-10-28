"""
security.py - Core Security Controls for Secure Multi-Domain Payment Company.
Demonstrates:
  1. Cryptographic Password Hashing (PBKDF2/SHA256 via Werkzeug)
  2. Role-Based Access Control (RBAC) Decorators for CUSTOMER and ADMIN
  3. Strict Input Validation & Sanitization (preventing Injection & Malformed input)
  4. Security Audit Logging (never logging passwords or sensitive payment data)
  5. Session validation helpers
"""

import re
import functools
from flask import session, redirect, url_for, flash, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection

# Regular expression for email validation
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

# Username: alphanumeric, underscores, 3-25 chars
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,25}$')

# Demo Card: 16 digits, can be spaced or dashed
CARD_REGEX = re.compile(r'^\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}$')

# Demo CVV: 3 or 4 digits
CVV_REGEX = re.compile(r'^\d{3,4}$')


# -------------------------------------------------------------
# 1. Password Hashing Controls
# -------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    """
    Hashes a password using secure salt and PBKDF2/SHA256.
    Plaintext passwords are never stored in memory or disk.
    """
    return generate_password_hash(plain_password, method="scrypt")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored cryptographic hash.
    Constant-time comparison protects against timing attacks.
    """
    return check_password_hash(hashed_password, plain_password)


# -------------------------------------------------------------
# 2. Input Validation Controls
# -------------------------------------------------------------
def validate_registration_input(username, email, password):
    """
    Validates user registration input.
    Returns (is_valid: bool, error_message: str or None)
    """
    if not username or not USERNAME_REGEX.match(username.strip()):
        return False, "Username must be 3-25 characters long and contain only letters, numbers, and underscores."
    
    if not email or not EMAIL_REGEX.match(email.strip()):
        return False, "Please provide a valid email address."
    
    # Password policy: At least 8 characters, with letters and numbers
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    has_letter = re.search(r'[a-zA-Z]', password)
    has_digit = re.search(r'[0-9]', password)
    if not (has_letter and has_digit):
        return False, "Password must contain both letters and at least one number."
    
    return True, None


def validate_payment_input(amount, card_number, exp_date, cvv):
    """
    Validates payment simulation input.
    Ensures safe constraints without storing or handling sensitive raw data.
    """
    # Amount validation: must be a positive float within safe limits
    try:
        amt = float(amount)
        if amt <= 0:
            return False, "Payment amount must be greater than $0.00."
        if amt > 10000.00:
            return False, "Demo payment maximum limit is $10,000.00."
    except (ValueError, TypeError):
        return False, "Invalid amount format. Please enter a valid numerical value."

    # Demo card format validation
    clean_card = str(card_number).replace(" ", "").replace("-", "").strip()
    if not clean_card.isdigit() or len(clean_card) != 16:
        return False, "Invalid card number. Demo cards must be 16 digits (e.g., 4111 1111 1111 1111)."

    # CVV validation
    clean_cvv = str(cvv).strip()
    if not CVV_REGEX.match(clean_cvv):
        return False, "Invalid CVV format (must be 3 or 4 digits)."

    # Expiry format validation (MM/YY)
    if not exp_date or not re.match(r'^(0[1-9]|1[0-2])\/?([0-9]{2})$', exp_date.strip()):
        return False, "Invalid expiration date format. Use MM/YY."

    return True, None


# -------------------------------------------------------------
# 3. Security Audit Logging
# -------------------------------------------------------------
def log_security_event(user_id, action, result, ip_address=None):
    """
    Records security-relevant events into the security_logs table.
    CRITICAL: Never passes passwords, CVVs, or full card numbers into the log.
    Allowed results: 'SUCCESS', 'FAILURE', 'BLOCKED'
    """
    if ip_address is None:
        ip_address = request.remote_addr if request else "127.0.0.1"

    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO security_logs (user_id, action, result, ip_address)
            VALUES (?, ?, ?, ?);
        """, (user_id, action, result, ip_address))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Security Log Error] Failed to write security log: {e}")


# -------------------------------------------------------------
# 4. Role-Based Access Control (RBAC) Decorators
# -------------------------------------------------------------
def login_required(f):
    """
    Ensures the user is logged into an active session.
    Protects both HTML routes and API endpoints.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            # Check if this is an API call
            if request.path.startswith("/api/"):
                log_security_event(None, f"API_ACCESS_DENIED:{request.path}", "BLOCKED")
                return jsonify({"error": "Authentication required. Please log in."}), 401
            
            log_security_event(None, f"UNAUTHORIZED_ACCESS:{request.path}", "BLOCKED")
            flash("You must be logged in to view this protected page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(required_role):
    """
    Ensures the authenticated user has the designated role (e.g. 'ADMIN').
    Blocks privilege escalation attempts and logs the incident.
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if logged in first
            if "user_id" not in session:
                if request.path.startswith("/api/"):
                    log_security_event(None, f"API_ADMIN_ACCESS_DENIED:{request.path}", "BLOCKED")
                    return jsonify({"error": "Authentication required."}), 401
                
                flash("Authentication required. Please log in as an administrator.", "warning")
                return redirect(url_for("admin_login"))

            user_role = session.get("role")
            if user_role != required_role:
                # Log privilege violation
                log_security_event(
                    session.get("user_id"),
                    f"PRIVILEGE_VIOLATION: User '{session.get('username')}' attempted to access '{request.path}' without '{required_role}' role.",
                    "BLOCKED"
                )
                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Forbidden. You do not have permission to access this administrative resource."
                    }), 403

                flash("Access denied: You do not have permission to access the Administrative Portal.", "danger")
                return redirect(url_for("customer_dashboard"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator
