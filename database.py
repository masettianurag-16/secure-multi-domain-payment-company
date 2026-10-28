"""
database.py - Database Layer for Secure Multi-Domain Payment Company Prototype.
Uses Python's built-in sqlite3 database.
Demonstrates:
  - Small, structured relational database schema
  - Prepared statements to prevent SQL Injection
  - Secure seeding of default hashed accounts
"""

import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_NAME = "secure_payment.db"

def get_db_connection():
    """
    Returns a thread-safe connection to the SQLite database with Row mapping.
    Row mapping allows column access by name (e.g., row['username']).
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database tables if they do not exist,
    and seeds default demo accounts with hashed passwords.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('CUSTOMER', 'ADMIN')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. transactions table
    # IMPORTANT: Never store raw card numbers, CVVs, or bank credentials.
    # Only store safe metadata: transaction_id, user_id, amount, status, demo_card_last4, created_at.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILED')),
        transaction_id TEXT UNIQUE NOT NULL,
        demo_card_last4 TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 3. security_logs table
    # Used for audit trails and monitoring security events.
    # NEVER log sensitive credentials or card data.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    conn.commit()

    # Seed initial demonstration accounts if table is empty
    cursor.execute("SELECT COUNT(*) as count FROM users;")
    count = cursor.fetchone()["count"]

    if count == 0:
        print("[Database] Seeding initial demo accounts...")
        # Admin account: admin / Admin@12345
        admin_hash = generate_password_hash("Admin@12345")
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?);
        """, ("admin", "admin@securepay.local", admin_hash, "ADMIN"))

        # Customer account: alice / Alice@12345
        customer_hash = generate_password_hash("Alice@12345")
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?);
        """, ("alice", "alice@customer.local", customer_hash, "CUSTOMER"))

        conn.commit()

        # Seed initial sample transaction for Alice
        cursor.execute("SELECT id FROM users WHERE username = 'alice';")
        alice_id = cursor.fetchone()["id"]
        cursor.execute("""
            INSERT INTO transactions (user_id, amount, status, transaction_id, demo_card_last4)
            VALUES (?, ?, ?, ?, ?);
        """, (alice_id, 25.50, "SUCCESS", "TXN-DEMO-INIT-001", "1111"))

        # Log system initialization in security logs
        cursor.execute("""
            INSERT INTO security_logs (user_id, action, result, ip_address)
            VALUES (?, ?, ?, ?);
        """, (None, "SYSTEM_INITIALIZATION", "SUCCESS", "127.0.0.1"))

        conn.commit()
        print("[Database] Database initialized and seeded successfully.")

    conn.close()

if __name__ == "__main__":
    init_db()
