import hashlib
import time
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from database_manager import db_manager

class SecurityManager:
    def __init__(self):
        self.max_login_attempts = 5
        self.lockout_duration = 900  # 15 minutes
        self.session_timeout = 1800  # 30 minutes
        
    def init_security_db(self):
        # Tables should be created by DatabaseManager or central init
        pass
    
    def validate_password_strength(self, password):
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
        if self.is_account_suspended(username):
            return True
        
        query = "SELECT failed_attempts, locked_until FROM users WHERE username=?"
        result = db_manager.execute_query(query, (username,), fetch_one=True)
        
        if not result:
            return False
            
        failed_attempts = result['failed_attempts'] if isinstance(result, dict) else result[0]
        locked_until = result['locked_until'] if isinstance(result, dict) else result[1]
        
        if locked_until:
            lock_time = datetime.fromisoformat(locked_until)
            if datetime.now() < lock_time:
                return True
            else:
                self.unlock_account(username)
                return False
        
        return (failed_attempts or 0) >= self.max_login_attempts
    
    def record_failed_attempt(self, username, ip_address):
        db_manager.execute_query(
            "UPDATE users SET failed_attempts = COALESCE(failed_attempts, 0) + 1 WHERE username=?",
            (username,)
        )
        
        result = db_manager.execute_query(
            "SELECT failed_attempts FROM users WHERE username=?",
            (username,), fetch_one=True
        )
        attempts = result['failed_attempts'] if isinstance(result, dict) else result[0]
        
        if attempts >= self.max_login_attempts:
            lock_until = datetime.now() + timedelta(seconds=self.lockout_duration)
            db_manager.execute_query(
                "UPDATE users SET locked_until=? WHERE username=?", 
                (lock_until.isoformat(), username)
            )
        
        self.log_security_event(username, ip_address, "LOGIN_FAILED", "FAILED", f"Failed attempt #{attempts}")
    
    def record_successful_login(self, username, ip_address):
        db_manager.execute_query(
            "UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE username=?", 
            (datetime.now().isoformat(), username)
        )
        self.log_security_event(username, ip_address, "LOGIN_SUCCESS", "SUCCESS", "User logged in")
    
    def is_account_suspended(self, username):
        result = db_manager.execute_query("SELECT suspended FROM users WHERE username=?", (username,), fetch_one=True)
        suspended = result['suspended'] if isinstance(result, dict) else (result[0] if result else 0)
        return (suspended == 1)
    
    def suspend_account(self, username):
        db_manager.execute_query("UPDATE users SET suspended=1 WHERE username=?", (username,))
    
    def unsuspend_account(self, username):
        db_manager.execute_query("UPDATE users SET suspended=0 WHERE username=?", (username,))
    
    def unlock_account(self, username):
        db_manager.execute_query("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
    
    def log_security_event(self, username, ip_address, action, status, details):
        db_manager.execute_query(
            "INSERT INTO security_logs (timestamp, username, ip_address, action, status, details) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), username, ip_address, action, status, details)
        )
    
    def create_session(self, username, session_id, ip_address):
        db_manager.execute_query("UPDATE user_sessions SET is_active=0 WHERE username=?", (username,))
        db_manager.execute_query(
            "INSERT INTO user_sessions (username, session_id, ip_address, created_at, last_activity) VALUES (?, ?, ?, ?, ?)",
            (username, session_id, ip_address, datetime.now().isoformat(), datetime.now().isoformat())
        )
    
    def validate_session(self, username, session_id):
        result = db_manager.execute_query(
            "SELECT last_activity FROM user_sessions WHERE username=? AND session_id=? AND is_active=1",
            (username, session_id), fetch_one=True
        )
        
        if not result:
            return False
        
        last_activity_str = result['last_activity'] if isinstance(result, dict) else result[0]
        last_activity = datetime.fromisoformat(last_activity_str)
        if datetime.now() - last_activity > timedelta(seconds=self.session_timeout):
            db_manager.execute_query("UPDATE user_sessions SET is_active=0 WHERE username=? AND session_id=?", (username, session_id))
            return False
        
        db_manager.execute_query(
            "UPDATE user_sessions SET last_activity=? WHERE username=? AND session_id=?",
            (datetime.now().isoformat(), username, session_id)
        )
        return True
    
    def get_user_audit_log(self, username, limit=50):
        query = "SELECT timestamp, ip_address, action, status, details FROM security_logs WHERE username=? ORDER BY timestamp DESC LIMIT ?"
        return db_manager.execute_query(query, (username, limit), fetch_all=True)

# Rate limiting remains the same as it is in-memory
login_attempts = {}
def rate_limit(max_attempts=10, window=300):
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
            login_attempts[ip] = [a for a in login_attempts[ip] if current_time - a < window]
            if len(login_attempts[ip]) >= max_attempts:
                return abort(429, description="Too many attempts")
            login_attempts[ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

security_manager = SecurityManager()