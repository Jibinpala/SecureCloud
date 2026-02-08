import sqlite3
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from crypto import encrypt_file, decrypt_file

def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()

    # Check for email columns
    c.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in c.fetchall()]
    
    if "email" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "email_hash" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN email_hash TEXT")

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        email TEXT,
        email_hash TEXT
    )
    """)
    conn.commit()
    conn.close()

def register_user(username, password, email=None):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    encrypted_email = None
    email_hash = None
    if email:
        encrypted_email = encrypt_file(email.encode()).decode()
        email_hash = hash_email(email)
        
    c.execute(
        "INSERT INTO users (username, password, role, email, email_hash) VALUES (?,?,?,?,?)",
        (username, generate_password_hash(password), "user", encrypted_email, email_hash)
    )
    conn.commit()
    conn.close()

def verify_user(username, password):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute(
        "SELECT password, role, suspended FROM users WHERE username=?",
        (username,)
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return None
    
    suspended = row[2] if len(row) > 2 else 0
    if suspended:
        return None
    
    if check_password_hash(row[0], password):
        return row[1]
    return None

def reset_password(username, email, new_password):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Use hash for lookup to avoid full table scan/decryption
    e_hash = hash_email(email)
    
    c.execute(
        "SELECT id FROM users WHERE username=? AND email_hash=?",
        (username, e_hash)
    )
    user = c.fetchone()
    if user:
        c.execute(
            "UPDATE users SET password=? WHERE id=?",
            (generate_password_hash(new_password), user[0])
        )
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False
