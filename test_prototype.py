"""
test_prototype.py - Automated Verification Suite for College Demonstration.
Verifies all 12 college demonstration steps and cybersecurity constraints:
  - Multi-domain routing
  - Password hashing (no plaintext)
  - Role-Based Access Control (RBAC: CUSTOMER vs ADMIN)
  - Input validation & weak password rejection
  - Demo payment simulation & card masking (no CVVs in DB)
  - Security audit logging of successes, failures, and blocked attempts
  - REST API endpoint security
"""

import sys
import os
import sqlite3
from app import app
from database import init_db, get_db_connection, DB_NAME

def run_tests():
    print("=" * 70)
    print("  RUNNING SECURE MULTI-DOMAIN PAYMENT COMPANY VERIFICATION SUITE")
    print("=" * 70)

    # Clean previous test database to ensure fresh run
    if os.path.exists(DB_NAME):
        try:
            os.remove(DB_NAME)
        except Exception:
            pass

    init_db()
    client = app.test_client()

    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [PASS] Step {total}: {name}")
        else:
            print(f"  [FAIL] Step {total}: {name}")
            if details:
                print(f"         Details: {details}")

    # Step 1: Database Initialization & Seeding
    conn = get_db_connection()
    admin_user = conn.execute("SELECT * FROM users WHERE username = 'admin';").fetchone()
    alice_user = conn.execute("SELECT * FROM users WHERE username = 'alice';").fetchone()
    conn.close()

    assert_test(
        "Database Initialized & Seeded with 'admin' and 'alice'",
        admin_user is not None and alice_user is not None,
        "Seed accounts not found"
    )

    # Step 2: Verify Passwords are Cryptographically Hashed (No plaintext)
    assert_test(
        "Passwords stored as cryptographic hashes (No plaintext)",
        admin_user["password_hash"].startswith("scrypt:") and "Admin@12345" not in admin_user["password_hash"],
        f"Password hash format unexpected: {admin_user['password_hash']}"
    )

    # Step 3: Registration with Weak Password Rejected
    res_weak = client.post("/register", data={
        "username": "charlie",
        "email": "charlie@test.local",
        "password": "weak",
        "confirm_password": "weak"
    }, follow_redirects=True)
    assert_test(
        "Password Policy: Reject weak password (< 8 chars)",
        b"Password must be at least 8 characters long" in res_weak.data
    )

    # Step 4: Register Valid Customer
    res_reg = client.post("/register", data={
        "username": "bob",
        "email": "bob@student.local",
        "password": "Password@123",
        "confirm_password": "Password@123"
    }, follow_redirects=True)
    assert_test(
        "Customer Registration: Valid account created ('bob')",
        b"Account registered successfully" in res_reg.data
    )

    # Step 5: Duplicate Registration Prevented
    res_dup = client.post("/register", data={
        "username": "bob",
        "email": "bob_other@student.local",
        "password": "Password@123",
        "confirm_password": "Password@123"
    }, follow_redirects=True)
    assert_test(
        "Input Validation: Duplicate username rejected",
        b"Username or Email already registered" in res_dup.data
    )

    # Step 6: Failed Login Logging
    res_fail = client.post("/login", data={
        "identifier": "bob",
        "password": "WrongPassword!"
    }, follow_redirects=True)
    assert_test(
        "Authentication: Failed login rejected with safe error",
        b"Invalid credentials" in res_fail.data
    )

    # Check security log for failed login
    conn = get_db_connection()
    failed_log = conn.execute("SELECT * FROM security_logs WHERE action LIKE '%LOGIN_FAILURE%' ORDER BY id DESC;").fetchone()
    conn.close()
    assert_test(
        "Audit Logging: Login failure recorded in security_logs",
        failed_log is not None and failed_log["result"] == "FAILURE"
    )

    # Step 7: Successful Customer Login
    res_login = client.post("/login", data={
        "identifier": "bob",
        "password": "Password@123"
    }, follow_redirects=True)
    assert_test(
        "Authentication: Successful login redirected to Customer Dashboard",
        b"Customer Dashboard" in res_login.data and b"Welcome, bob" in res_login.data
    )

    # Step 8: Demo Payment Processing & Card Masking
    res_pay = client.post("/payment/process", data={
        "amount": "49.99",
        "card_number": "4111 1111 1111 1111",
        "exp_date": "12/28",
        "cvv": "123",
        "note": "Textbook Order"
    }, follow_redirects=True)
    assert_test(
        "Payment Application: Demo payment processed successfully",
        b"Payment Successful" in res_pay.data and b"$49.99 USD" in res_pay.data
    )

    # Verify database state for payment: No CVV column and card masked to last 4
    conn = get_db_connection()
    tx = conn.execute("SELECT * FROM transactions WHERE amount = 49.99;").fetchone()
    columns = [col[1] for col in conn.execute("PRAGMA table_info(transactions);").fetchall()]
    conn.close()

    assert_test(
        "Payment Security: Zero CVV storage & card masked to last 4 digits",
        "cvv" not in columns and tx["demo_card_last4"] == "1111" and tx["status"] == "SUCCESS",
        f"Columns found: {columns}, last4: {tx['demo_card_last4'] if tx else 'None'}"
    )

    # Step 9: Customer Blocked from Admin Portal (RBAC Enforcement)
    res_admin_block = client.get("/admin/dashboard", follow_redirects=True)
    assert_test(
        "RBAC Enforcement: Customer blocked from accessing /admin/dashboard",
        b"Access denied: You do not have permission" in res_admin_block.data
    )

    # Check security log for blocked privilege violation
    conn = get_db_connection()
    blocked_log = conn.execute("SELECT * FROM security_logs WHERE result = 'BLOCKED' ORDER BY id DESC;").fetchone()
    conn.close()
    assert_test(
        "Audit Logging: RBAC violation captured with 'BLOCKED' result",
        blocked_log is not None and "PRIVILEGE_VIOLATION" in blocked_log["action"]
    )

    # Step 10: Customer Logout & Unauthenticated Access Blocked
    client.get("/logout", follow_redirects=True)
    res_unauth = client.get("/customer/dashboard", follow_redirects=True)
    assert_test(
        "Session Security: Customer dashboard inaccessible after logout",
        b"You must be logged in to view this protected page" in res_unauth.data
    )

    # Step 11: Admin Login & Access to Admin Console
    res_admin_login = client.post("/admin/login", data={
        "username": "admin",
        "password": "Admin@12345"
    }, follow_redirects=True)
    assert_test(
        "Admin Portal: Admin authenticated and dashboard loaded",
        b"Administrative Control Console" in res_admin_login.data
    )

    res_admin_users = client.get("/admin/users")
    assert_test(
        "Admin Portal: Admin can view user database with concealed passwords",
        b"Registered System Users" in res_admin_users.data and b"Hashed (Hidden)" in res_admin_users.data
    )

    res_admin_logs = client.get("/admin/logs")
    assert_test(
        "Admin Portal: Admin can view real-time security audit logs",
        b"Security &amp; Audit Event Logs" in res_admin_logs.data
    )

    # Step 12: REST API Endpoint Protection Verification
    api_login_res = client.post("/api/auth/login", json={
        "identifier": "alice",
        "password": "Alice@12345"
    })
    assert_test(
        "REST API: /api/auth/login returns JSON status and user metadata",
        api_login_res.status_code == 200 and api_login_res.get_json().get("status") == "success"
    )

    api_profile_res = client.get("/api/customer/profile")
    assert_test(
        "REST API: /api/customer/profile protected and returns profile data",
        api_profile_res.status_code == 200 and api_profile_res.get_json()["profile"]["username"] == "alice"
    )

    # Ensure passwords are NOT in API profile response
    assert_test(
        "REST API Security: Password hash NOT exposed in API profile",
        "password_hash" not in api_profile_res.get_json()["profile"]
    )

    # Logout API
    client.post("/api/auth/logout")
    api_unauth = client.get("/api/customer/profile")
    assert_test(
        "REST API Security: Unauthenticated request rejected with HTTP 401",
        api_unauth.status_code == 401
    )

    print("-" * 70)
    print(f"  VERIFICATION RESULTS: {passed}/{total} TESTS PASSED")
    print("=" * 70)

    return passed == total

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
