from flask import Flask, render_template, request, redirect, session, flash, jsonify
from auth import init_db, register_user, verify_user
from crypto import encrypt_file
from admin import get_all_users, get_all_files
from security import security_manager, rate_limit
import os
import random
import string
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

init_db()

BASE_UPLOAD = "encrypted_files/users"
os.makedirs(BASE_UPLOAD, exist_ok=True)

def require_auth(role=None):
    """Decorator to require authentication and optional role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect("/")
            
            # Validate session
            if not security_manager.validate_session(session.get("user"), session.get("session_id")):
                session.clear()
                flash("Session expired. Please login again.")
                return redirect("/")
            
            # Check role if specified
            if role and session.get("role") != role:
                return redirect("/")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/", methods=["GET", "POST"])
@rate_limit(max_attempts=10, window=300)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_input = request.form.get("captcha", "")
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Validate inputs
        if not username or not password or not captcha_input:
            flash("All fields are required")
            return redirect("/")
        
        # Check captcha
        if captcha_input.upper() != session.get("captcha", "").upper():
            security_manager.log_security_event(username, ip_address, "CAPTCHA_FAILED", "FAILED", "Invalid captcha")
            flash("Invalid captcha")
            return redirect("/")
        
        # Check if account is locked
        if security_manager.is_account_locked(username):
            security_manager.log_security_event(username, ip_address, "LOGIN_BLOCKED", "BLOCKED", "Account locked")
            flash("Account is temporarily locked due to multiple failed attempts")
            return redirect("/")
        
        # Verify credentials
        role = verify_user(username, password)
        
        if role:
            # Successful login
            session_id = secrets.token_hex(32)
            session["user"] = username
            session["role"] = role
            session["session_id"] = session_id
            session["login_time"] = datetime.now().isoformat()
            session.permanent = True
            
            security_manager.record_successful_login(username, ip_address)
            security_manager.create_session(username, session_id, ip_address)
            
            return redirect("/admin" if role == "admin" else "/dashboard")
        else:
            # Failed login
            security_manager.record_failed_attempt(username, ip_address)
            flash("Invalid credentials")
            return redirect("/")
    
    # Generate secure captcha
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session["captcha"] = captcha
    return render_template("login.html", captcha=captcha)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Validate inputs
        if not username or not password:
            flash("Username and password are required")
            return render_template("register.html")
        
        # Validate password strength
        is_strong, message = security_manager.validate_password_strength(password)
        if not is_strong:
            flash(message)
            return render_template("register.html")
        
        try:
            register_user(username, password)
            security_manager.log_security_event(username, ip_address, "REGISTER", "SUCCESS", "New user registered")
            flash("Account created successfully! Please login.")
            return redirect("/")
        except Exception as e:
            security_manager.log_security_event(username, ip_address, "REGISTER", "FAILED", str(e))
            flash("Username already exists or registration failed")
            return render_template("register.html")
    
    return render_template("register.html")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        if not username:
            flash("Username is required")
            return render_template("forgot_password.html")
        
        # Generate temporary password
        temp_password = secrets.token_urlsafe(12)
        
        try:
            # Update user password
            conn = sqlite3.connect("database/users.db")
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE username=?", (username,))
            if c.fetchone():
                from werkzeug.security import generate_password_hash
                hashed_temp = generate_password_hash(temp_password)
                c.execute("UPDATE users SET password=?, failed_attempts=0, locked_until=NULL WHERE username=?", 
                         (hashed_temp, username))
                conn.commit()
                
                security_manager.log_security_event(username, ip_address, "PASSWORD_RESET", "SUCCESS", 
                                                   "Temporary password generated")
                
                flash(f"Temporary password generated: {temp_password}")
                flash("Please login with this temporary password and change it immediately.")
            else:
                flash("Username not found")
                security_manager.log_security_event(username, ip_address, "PASSWORD_RESET", "FAILED", 
                                                   "Username not found")
            
            conn.close()
        except Exception as e:
            flash("Password reset failed. Please try again.")
            security_manager.log_security_event(username, ip_address, "PASSWORD_RESET", "FAILED", str(e))
        
        return render_template("forgot_password.html")
    
    return render_template("forgot_password.html")

@app.route("/dashboard", methods=["GET", "POST"])
@require_auth(role="user")
def dashboard():
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    os.makedirs(user_folder, exist_ok=True)
    
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected")
            return render_template("dashboard.html")
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected")
            return render_template("dashboard.html")
        
        # Validate file size (max 10MB)
        file_content = file.read()
        if len(file_content) > 10 * 1024 * 1024:
            flash("File too large. Maximum size is 10MB.")
            return render_template("dashboard.html")
        
        try:
            encrypted = encrypt_file(file_content)
            file_path = os.path.join(user_folder, file.filename)
            
            with open(file_path, "wb") as f:
                f.write(encrypted)
            
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            security_manager.log_security_event(session["user"], ip_address, "FILE_UPLOAD", "SUCCESS", 
                                               f"Uploaded: {file.filename}")
            flash(f"File '{file.filename}' uploaded and encrypted successfully!")
        except Exception as e:
            flash(f"Upload failed: {str(e)}")
    
    return render_template("dashboard.html")

@app.route("/admin")
@require_auth(role="admin")
def admin_panel():
    return render_template(
        "admin_dashboard.html",
        users=get_all_users(),
        files=get_all_files()
    )

@app.route("/admin/security")
@require_auth(role="admin")
def security_dashboard():
    logs = security_manager.get_security_logs(50)
    return render_template("security_dashboard.html", logs=logs)

@app.route("/admin/unlock/<username>")
@require_auth(role="admin")
def unlock_user(username):
    security_manager.unlock_account(username)
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    security_manager.log_security_event(session["user"], ip_address, "UNLOCK_ACCOUNT", "SUCCESS", 
                                       f"Unlocked user: {username}")
    flash(f"Account {username} has been unlocked")
    return redirect("/admin")

@app.route("/logout")
def logout():
    if "user" in session:
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        security_manager.log_security_event(session["user"], ip_address, "LOGOUT", "SUCCESS", "User logged out")
    
    session.clear()
    flash("You have been logged out successfully")
    return redirect("/")

@app.before_request
def security_headers():
    """Add security headers to all responses"""
    pass

@app.after_request
def after_request(response):
    """Add security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response

if __name__ == "__main__":
    app.run(debug=True)  # Run without SSL for development