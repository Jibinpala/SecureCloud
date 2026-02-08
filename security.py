import sqlite3
import hashlib
import time
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re

class SecurityManager:
    def __init__(self):
        self.init_security_db()
        self.max_login_attempts = 5
        self.lockout_duration = 900  # 15 minutes
        self.session_timeout = 1800  # 30 minutes
        
    def init_security_db(self):
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        # Check which columns exist and add missing ones
        c.execute("PRAGMA table_info(users)")
        existing_columns = {row[1] for row in c.fetchall()}
        
        # Add missing security columns
        columns_to_add = [
            ("failed_attempts", "INTEGER DEFAULT 0"),
            ("locked_until", "TEXT"),
            ("last_login", "TEXT"),
            ("password_changed", "TEXT"),
            ("suspended", "INTEGER DEFAULT 0"),
            ("totp_secret", "TEXT"),
            ("mfa_enabled", "INTEGER DEFAULT 0")
        ]
        
        for col_name, col_type in columns_to_add:
            if col_name not in existing_columns:
                try:
                    c.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column might already exist or other issue
            
        # Create security logs table
        c.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            ip_address TEXT,
            action TEXT,
            status TEXT,
            details TEXT
        )
        """)
        
        # Create sessions table
        c.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            session_id TEXT,
            ip_address TEXT,
            created_at TEXT,
            last_activity TEXT,
            is_active INTEGER DEFAULT 1
        )
        """)
        
        conn.commit()
        conn.close()
    
    def validate_password_strength(self, password):
        """Validate password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        return True, "Password is strong"
    
    def is_account_locked(self, username):
        """Check if account is locked due to failed attempts or suspension"""
        # Check suspension first
        if self.is_account_suspended(username):
            return True
        
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        c.execute("SELECT failed_attempts, locked_until FROM users WHERE username=?", (username,))
        result = c.fetchone()
        conn.close()
        
        if not result:
            return False
            
        failed_attempts, locked_until = result
        
        if locked_until:
            lock_time = datetime.fromisoformat(locked_until)
            if datetime.now() < lock_time:
                return True
            else:
                # Unlock account
                self.unlock_account(username)
                return False
        
        return failed_attempts >= self.max_login_attempts
    
    def record_failed_attempt(self, username, ip_address):
        """Record failed login attempt"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        # Increment failed attempts
        c.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username=?", (username,))
        
        # Check if should lock account
        c.execute("SELECT failed_attempts FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if result and result[0] >= self.max_login_attempts:
            lock_until = datetime.now() + timedelta(seconds=self.lockout_duration)
            c.execute("UPDATE users SET locked_until=? WHERE username=?", 
                     (lock_until.isoformat(), username))
        
        conn.commit()
        conn.close()
        
        self.log_security_event(username, ip_address, "LOGIN_FAILED", "FAILED", 
                               f"Failed attempt #{result[0] if result else 1}")
    
    def record_successful_login(self, username, ip_address):
        """Record successful login and reset failed attempts"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        c.execute("""UPDATE users SET 
                     failed_attempts=0, 
                     locked_until=NULL, 
                     last_login=? 
                     WHERE username=?""", 
                 (datetime.now().isoformat(), username))
        
        conn.commit()
        conn.close()
        
        self.log_security_event(username, ip_address, "LOGIN_SUCCESS", "SUCCESS", "User logged in")
    
    def is_account_suspended(self, username):
        """Check if account is suspended by admin"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        c.execute("SELECT suspended FROM users WHERE username=?", (username,))
        result = c.fetchone()
        conn.close()
        return result and result[0] == 1 if result else False
    
    def suspend_account(self, username):
        """Suspend user account (admin action)"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET suspended=1 WHERE username=?", (username,))
        conn.commit()
        conn.close()
    
    def unsuspend_account(self, username):
        """Unsuspend user account (admin action)"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET suspended=0 WHERE username=?", (username,))
        conn.commit()
        conn.close()
    
    def unlock_account(self, username):
        """Unlock user account"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
        conn.commit()
        conn.close()
    
    def log_security_event(self, username, ip_address, action, status, details):
        """Log security events"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        c.execute("""INSERT INTO security_logs 
                     (timestamp, username, ip_address, action, status, details)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                 (datetime.now().isoformat(), username, ip_address, action, status, details))
        
        conn.commit()
        conn.close()
    
    def create_session(self, username, session_id, ip_address):
        """Create user session"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        # Deactivate old sessions
        c.execute("UPDATE user_sessions SET is_active=0 WHERE username=?", (username,))
        
        # Create new session
        c.execute("""INSERT INTO user_sessions 
                     (username, session_id, ip_address, created_at, last_activity)
                     VALUES (?, ?, ?, ?, ?)""",
                 (username, session_id, ip_address, 
                  datetime.now().isoformat(), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def validate_session(self, username, session_id):
        """Validate user session"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        c.execute("""SELECT last_activity FROM user_sessions 
                     WHERE username=? AND session_id=? AND is_active=1""",
                 (username, session_id))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return False
        
        last_activity = datetime.fromisoformat(result[0])
        if datetime.now() - last_activity > timedelta(seconds=self.session_timeout):
            # Session expired
            c.execute("UPDATE user_sessions SET is_active=0 WHERE username=? AND session_id=?",
                     (username, session_id))
            conn.commit()
            conn.close()
            return False
        
        # Update last activity
        c.execute("""UPDATE user_sessions SET last_activity=? 
                     WHERE username=? AND session_id=?""",
                 (datetime.now().isoformat(), username, session_id))
        
        conn.commit()
        conn.close()
        return True
    
    def get_security_logs(self, limit=100):
        """Get recent security logs (admin)"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        c.execute("""SELECT timestamp, username, ip_address, action, status, details
                     FROM security_logs 
                     ORDER BY timestamp DESC 
                     LIMIT ?""", (limit,))
        
        logs = c.fetchall()
        conn.close()
        return logs
    
    def get_user_audit_log(self, username, limit=50):
        """Get security logs for a specific user"""
        conn = sqlite3.connect("database/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute("""SELECT timestamp, ip_address, action, status, details
                     FROM security_logs 
                     WHERE username=? 
                     ORDER BY timestamp DESC 
                     LIMIT ?""", (username, limit))
        
        logs = [dict(row) for row in c.fetchall()]
        conn.close()
        return logs
    
    def get_login_history(self, username, limit=10):
        """Get user login history"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        c.execute("""SELECT timestamp, ip_address, status, details
                     FROM security_logs 
                     WHERE username=? AND action LIKE 'LOGIN%'
                     ORDER BY timestamp DESC 
                     LIMIT ?""", (username, limit))
        
        history = c.fetchall()
        conn.close()
        return history

# Rate limiting decorator
login_attempts = {}

def rate_limit(max_attempts=10, window=300):  # 10 attempts per 5 minutes
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, abort
            
            if request.method != "POST":
                return f(*args, **kwargs)
                
            ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            current_time = time.time()
            
            if ip not in login_attempts:
                login_attempts[ip] = []
            
            # Clean old attempts
            login_attempts[ip] = [attempt for attempt in login_attempts[ip] 
                                if current_time - attempt < window]
            
            if len(login_attempts[ip]) >= max_attempts:
                return abort(429, description="Too many login attempts. Please wait 5 minutes.")
            
            login_attempts[ip].append(current_time)
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Initialize security manager
security_manager = SecurityManager()