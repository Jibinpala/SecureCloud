from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file
from auth import init_db, register_user, verify_user
from crypto import encrypt_file, decrypt_file
from admin import get_all_users, get_all_files
from security import security_manager, rate_limit
import os
import random
import string
import hashlib
import secrets
import sqlite3
import pyotp
import qrcode
import io
import base64
import tempfile
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

init_db()

BASE_UPLOAD = "encrypted_files/users"
os.makedirs(BASE_UPLOAD, exist_ok=True)

def require_auth(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect("/")
            
            if not security_manager.validate_session(session.get("user"), session.get("session_id")):
                session.clear()
                flash("Session expired. Please login again.")
                return redirect("/")
            
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
        
        if not username or not password or not captcha_input:
            flash("All fields are required")
            return redirect("/")
        
        if captcha_input.upper() != session.get("captcha", "").upper():
            security_manager.log_security_event(username, ip_address, "CAPTCHA_FAILED", "FAILED", "Invalid captcha")
            flash("Invalid captcha")
            return redirect("/")
        
        if security_manager.is_account_locked(username):
            security_manager.log_security_event(username, ip_address, "LOGIN_BLOCKED", "BLOCKED", "Account locked")
            flash("Account is temporarily locked due to multiple failed attempts")
            return redirect("/")
        
        role = verify_user(username, password)
        
        if role:
            # Check if 2FA is enabled
            if has_2fa_enabled(username):
                session["temp_user"] = username
                session["temp_role"] = role
                return redirect("/verify_2fa")
            
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
            security_manager.record_failed_attempt(username, ip_address)
            flash("Invalid credentials")
            return redirect("/")
    
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session["captcha"] = captcha
    return render_template("login.html", captcha=captcha)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        if not username or not password:
            flash("Username and password are required")
            return render_template("register.html")
        
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
        
        temp_password = secrets.token_urlsafe(12)
        
        try:
            conn = sqlite3.connect("database/users.db")
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE username=?", (username,))
            if c.fetchone():
                hashed_temp = generate_password_hash(temp_password)
                c.execute("UPDATE users SET password=?, failed_attempts=0, locked_until=NULL WHERE username=?", 
                         (hashed_temp, username))
                conn.commit()
                
                security_manager.log_security_event(username, ip_address, "PASSWORD_RESET", "SUCCESS", 
                                                   "Temporary password generated")
                
                flash(f"Temporary password: {temp_password}")
                flash("Please login and change your password immediately.")
            else:
                flash("Username not found")
            
            conn.close()
        except Exception as e:
            flash("Password reset failed. Please try again.")
        
        return render_template("forgot_password.html")
    
    return render_template("forgot_password.html")

@app.route("/setup_2fa")
@require_auth()
def setup_2fa():
    username = session["user"]
    secret = pyotp.random_base32()
    
    # Store secret temporarily
    session["temp_2fa_secret"] = secret
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="SecureCloud"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    qr_code = base64.b64encode(img_io.getvalue()).decode()
    
    return render_template("setup_2fa.html", qr_code=qr_code, secret=secret)

@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "POST":
        token = request.form.get("token", "")
        
        if "temp_user" in session:
            # Login verification
            username = session["temp_user"]
            if verify_2fa_token(username, token):
                session_id = secrets.token_hex(32)
                session["user"] = username
                session["role"] = session["temp_role"]
                session["session_id"] = session_id
                session.permanent = True
                
                # Clear temp session
                session.pop("temp_user", None)
                session.pop("temp_role", None)
                
                return redirect("/admin" if session["role"] == "admin" else "/dashboard")
            else:
                flash("Invalid 2FA token")
        
        elif "temp_2fa_secret" in session:
            # Setup verification
            secret = session["temp_2fa_secret"]
            totp = pyotp.TOTP(secret)
            
            if totp.verify(token):
                # Save 2FA secret to database
                save_2fa_secret(session["user"], secret)
                session.pop("temp_2fa_secret", None)
                flash("2FA enabled successfully!")
                return redirect("/dashboard")
            else:
                flash("Invalid token. Please try again.")
    
    return render_template("verify_2fa.html")

@app.route("/dashboard", methods=["GET", "POST"])
@require_auth(role="user")
def dashboard():
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    os.makedirs(user_folder, exist_ok=True)
    
    if request.method == "POST":
        uploaded_files = request.files.getlist("file")
        
        for file in uploaded_files:
            if file and file.filename:
                if len(file.read()) > 10 * 1024 * 1024:
                    flash(f"File {file.filename} too large (max 10MB)")
                    continue
                
                file.seek(0)
                
                try:
                    encrypted = encrypt_file(file.read())
                    file_path = os.path.join(user_folder, file.filename)
                    
                    with open(file_path, "wb") as f:
                        f.write(encrypted)
                    
                    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                    security_manager.log_security_event(session["user"], ip_address, "FILE_UPLOAD", "SUCCESS", 
                                                       f"Uploaded: {file.filename}")
                except Exception as e:
                    flash(f"Upload failed for {file.filename}: {str(e)}")
        
        if uploaded_files:
            flash("Files uploaded successfully!")
    
    # Get user files
    user_files = get_user_files(session["user"])
    
    return render_template("dashboard.html", files=user_files)

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

@app.route("/share_file/<filename>")
@require_auth()
def share_file(filename):
    # Generate secure sharing link
    share_token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=24)
    
    # Store sharing info
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS file_shares (
        id INTEGER PRIMARY KEY,
        username TEXT,
        filename TEXT,
        share_token TEXT,
        expires_at TEXT
    )""")
    
    c.execute("INSERT INTO file_shares (username, filename, share_token, expires_at) VALUES (?, ?, ?, ?)",
              (session["user"], filename, share_token, expiry.isoformat()))
    conn.commit()
    conn.close()
    
    share_url = f"{request.host_url}download/{share_token}"
    return jsonify({"share_url": share_url, "expires": expiry.isoformat()})

@app.route("/download/<share_token>")
def download_shared_file(share_token):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("SELECT username, filename, expires_at FROM file_shares WHERE share_token=?", (share_token,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return "Invalid or expired link", 404
    
    username, filename, expires_at = result
    expiry = datetime.fromisoformat(expires_at)
    
    if datetime.now() > expiry:
        return "Link expired", 404
    
    file_path = os.path.join(BASE_UPLOAD, username, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename)
    
    return "File not found", 404

@app.route("/download_file/<filename>")
@require_auth()
def download_file(filename):
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    file_path = os.path.join(user_folder, filename)
    
    if os.path.exists(file_path):
        # Decrypt file before sending
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = decrypt_file(encrypted_data)
            
            # Create temporary decrypted file
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(decrypted_data)
            temp_file.close()
            
            return send_file(temp_file.name, as_attachment=True, download_name=filename)
        except Exception as e:
            flash(f"Download failed: {str(e)}")
            return redirect("/dashboard")
    
    return "File not found", 404

@app.route("/delete_file/<filename>", methods=["DELETE"])
@require_auth()
def delete_file(filename):
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    file_path = os.path.join(user_folder, filename)
    
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            security_manager.log_security_event(session["user"], ip_address, "FILE_DELETE", "SUCCESS", 
                                               f"Deleted: {filename}")
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "File not found"}), 404

@app.route("/logout")
def logout():
    if "user" in session:
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        security_manager.log_security_event(session["user"], ip_address, "LOGOUT", "SUCCESS", "User logged out")
    
    session.clear()
    flash("You have been logged out successfully")
    return redirect("/")

# Helper functions
def has_2fa_enabled(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    return result and result[0] is not None

def verify_2fa_token(username, token):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    
    if result and result[0]:
        totp = pyotp.TOTP(result[0])
        return totp.verify(token)
    return False

def save_2fa_secret(username, secret):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    except:
        pass
    c.execute("UPDATE users SET totp_secret=? WHERE username=?", (secret, username))
    conn.commit()
    conn.close()

def get_user_files(username):
    user_folder = os.path.join(BASE_UPLOAD, username)
    files = []
    
    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            file_path = os.path.join(user_folder, filename)
            if os.path.isfile(file_path):
                files.append({
                    'name': filename,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                })
    
    return files

@app.before_request
def security_headers():
    pass

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response

if __name__ == "__main__":
    app.run(debug=True)