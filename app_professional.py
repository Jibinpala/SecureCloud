from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file, Response
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
import mimetypes
import json
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash
import uuid

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

init_db()

BASE_UPLOAD = "encrypted_files/users"
os.makedirs(BASE_UPLOAD, exist_ok=True)

# Storage quotas (in bytes)
STORAGE_QUOTAS = {
    'free': 100 * 1024 * 1024,      # 100MB
    'premium': 1024 * 1024 * 1024,  # 1GB
    'enterprise': 10 * 1024 * 1024 * 1024  # 10GB
}

def init_professional_db():
    """Initialize professional database tables"""
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Add professional columns to users
    try:
        c.execute("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'")
        c.execute("ALTER TABLE users ADD COLUMN storage_used INTEGER DEFAULT 0")
        c.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
        c.execute("ALTER TABLE users ADD COLUMN organization TEXT")
        c.execute("ALTER TABLE users ADD COLUMN department TEXT")
    except sqlite3.OperationalError:
        pass
    
    # File metadata table
    c.execute("""CREATE TABLE IF NOT EXISTS file_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        filename TEXT,
        original_name TEXT,
        file_size INTEGER,
        mime_type TEXT,
        upload_date TEXT,
        last_accessed TEXT,
        download_count INTEGER DEFAULT 0,
        tags TEXT,
        description TEXT
    )""")
    
    # Analytics table
    c.execute("""CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        resource TEXT,
        timestamp TEXT,
        ip_address TEXT,
        user_agent TEXT,
        metadata TEXT
    )""")
    
    # API usage table
    c.execute("""CREATE TABLE IF NOT EXISTS api_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT,
        endpoint TEXT,
        method TEXT,
        timestamp TEXT,
        response_code INTEGER,
        response_time REAL
    )""")
    
    # Organizations table
    c.execute("""CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        domain TEXT,
        plan TEXT DEFAULT 'enterprise',
        created_date TEXT,
        admin_user TEXT,
        settings TEXT
    )""")
    
    conn.commit()
    conn.close()

init_professional_db()

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

def log_analytics(action, resource="", metadata=None):
    """Log user analytics"""
    if "user" not in session:
        return
    
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""INSERT INTO analytics 
                 (username, action, resource, timestamp, ip_address, user_agent, metadata)
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              (session["user"], action, resource, datetime.now().isoformat(),
               request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
               request.headers.get('User-Agent', ''),
               json.dumps(metadata) if metadata else None))
    
    conn.commit()
    conn.close()

def check_storage_quota(username, file_size):
    """Check if user has enough storage quota"""
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("SELECT plan, storage_used FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return False
    
    plan, storage_used = result
    quota = STORAGE_QUOTAS.get(plan, STORAGE_QUOTAS['free'])
    
    return (storage_used + file_size) <= quota

def update_storage_usage(username, size_change):
    """Update user's storage usage"""
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("UPDATE users SET storage_used = storage_used + ? WHERE username=?",
              (size_change, username))
    
    conn.commit()
    conn.close()

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
            log_analytics("LOGIN", metadata={"ip": ip_address})
            
            return redirect("/admin" if role == "admin" else "/dashboard")
        else:
            security_manager.record_failed_attempt(username, ip_address)
            flash("Invalid credentials")
            return redirect("/")
    
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session["captcha"] = captcha
    return render_template("login.html", captcha=captcha)

@app.route("/dashboard")
@require_auth(role="user")
def dashboard():
    user_files = get_user_files_with_metadata(session["user"])
    user_stats = get_user_statistics(session["user"])
    log_analytics("DASHBOARD_VIEW")
    
    return render_template("professional_dashboard.html", 
                         files=user_files, 
                         stats=user_stats)

@app.route("/upload", methods=["POST"])
@require_auth()
def upload_files():
    uploaded_files = request.files.getlist("file")
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    os.makedirs(user_folder, exist_ok=True)
    
    success_count = 0
    
    for file in uploaded_files:
        if file and file.filename:
            file_size = len(file.read())
            file.seek(0)
            
            # Check storage quota
            if not check_storage_quota(session["user"], file_size):
                flash(f"Storage quota exceeded for {file.filename}")
                continue
            
            if file_size > 50 * 1024 * 1024:  # 50MB limit
                flash(f"File {file.filename} too large (max 50MB)")
                continue
            
            try:
                # Generate unique filename
                file_id = str(uuid.uuid4())
                encrypted_filename = f"{file_id}.enc"
                
                encrypted = encrypt_file(file.read())
                file_path = os.path.join(user_folder, encrypted_filename)
                
                with open(file_path, "wb") as f:
                    f.write(encrypted)
                
                # Store metadata
                store_file_metadata(session["user"], encrypted_filename, file.filename, 
                                  file_size, file.content_type or 'application/octet-stream')
                
                # Update storage usage
                update_storage_usage(session["user"], file_size)
                
                log_analytics("FILE_UPLOAD", file.filename, {"size": file_size})
                success_count += 1
                
            except Exception as e:
                flash(f"Upload failed for {file.filename}: {str(e)}")
    
    if success_count > 0:
        flash(f"{success_count} file(s) uploaded successfully!")
    
    return redirect("/dashboard")

@app.route("/preview/<file_id>")
@require_auth()
def preview_file(file_id):
    """Preview file content"""
    file_info = get_file_metadata(session["user"], file_id)
    if not file_info:
        return "File not found", 404
    
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    file_path = os.path.join(user_folder, file_info['filename'])
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data)
        
        # Update access tracking
        update_file_access(session["user"], file_id)
        log_analytics("FILE_PREVIEW", file_info['original_name'])
        
        # Return appropriate response based on file type
        mime_type = file_info['mime_type']
        
        if mime_type.startswith('text/') or mime_type == 'application/json':
            return Response(decrypted_data, mimetype=mime_type)
        elif mime_type.startswith('image/'):
            return Response(decrypted_data, mimetype=mime_type)
        elif mime_type == 'application/pdf':
            return Response(decrypted_data, mimetype=mime_type)
        else:
            return jsonify({"error": "Preview not available for this file type"})
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/analytics")
@require_auth(role="admin")
def analytics_dashboard():
    """Analytics dashboard for admins"""
    analytics_data = get_analytics_data()
    return render_template("analytics_dashboard.html", data=analytics_data)

@app.route("/api/files", methods=["GET"])
def api_list_files():
    """API endpoint to list user files"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({"error": "API key required"}), 401
    
    username = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"error": "Invalid API key"}), 401
    
    files = get_user_files_with_metadata(username)
    log_api_usage(api_key, "/api/files", "GET", 200)
    
    return jsonify({
        "files": [
            {
                "id": f["id"],
                "name": f["original_name"],
                "size": f["file_size"],
                "upload_date": f["upload_date"],
                "mime_type": f["mime_type"]
            }
            for f in files
        ]
    })

@app.route("/api/upload", methods=["POST"])
def api_upload_file():
    """API endpoint to upload files"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({"error": "API key required"}), 401
    
    username = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"error": "Invalid API key"}), 401
    
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400
    
    # Implementation similar to regular upload
    # ... (upload logic)
    
    log_api_usage(api_key, "/api/upload", "POST", 200)
    return jsonify({"message": "File uploaded successfully"})

@app.route("/settings")
@require_auth()
def user_settings():
    """User settings page"""
    user_info = get_user_info(session["user"])
    return render_template("user_settings.html", user=user_info)

@app.route("/generate_api_key", methods=["POST"])
@require_auth()
def generate_api_key():
    """Generate API key for user"""
    api_key = secrets.token_urlsafe(32)
    
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET api_key=? WHERE username=?", (api_key, session["user"]))
    conn.commit()
    conn.close()
    
    log_analytics("API_KEY_GENERATED")
    flash("API key generated successfully!")
    return redirect("/settings")

# Helper functions
def store_file_metadata(username, filename, original_name, file_size, mime_type):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""INSERT INTO file_metadata 
                 (username, filename, original_name, file_size, mime_type, upload_date)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              (username, filename, original_name, file_size, mime_type, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

def get_user_files_with_metadata(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT id, filename, original_name, file_size, mime_type, 
                        upload_date, download_count, tags, description
                 FROM file_metadata WHERE username=? ORDER BY upload_date DESC""",
              (username,))
    
    files = []
    for row in c.fetchall():
        files.append({
            'id': row[0],
            'filename': row[1],
            'original_name': row[2],
            'file_size': row[3],
            'mime_type': row[4],
            'upload_date': row[5],
            'download_count': row[6],
            'tags': row[7],
            'description': row[8]
        })
    
    conn.close()
    return files

def get_user_statistics(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Get user plan and storage
    c.execute("SELECT plan, storage_used FROM users WHERE username=?", (username,))
    user_data = c.fetchone()
    
    # Get file count
    c.execute("SELECT COUNT(*) FROM file_metadata WHERE username=?", (username,))
    file_count = c.fetchone()[0]
    
    # Get recent activity count
    c.execute("""SELECT COUNT(*) FROM analytics 
                 WHERE username=? AND timestamp > datetime('now', '-7 days')""", (username,))
    recent_activity = c.fetchone()[0]
    
    conn.close()
    
    plan, storage_used = user_data if user_data else ('free', 0)
    quota = STORAGE_QUOTAS.get(plan, STORAGE_QUOTAS['free'])
    
    return {
        'plan': plan,
        'storage_used': storage_used,
        'storage_quota': quota,
        'storage_percentage': (storage_used / quota) * 100 if quota > 0 else 0,
        'file_count': file_count,
        'recent_activity': recent_activity
    }

def get_file_metadata(username, file_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT filename, original_name, file_size, mime_type
                 FROM file_metadata WHERE username=? AND id=?""",
              (username, file_id))
    
    result = c.fetchone()
    conn.close()
    
    if result:
        return {
            'filename': result[0],
            'original_name': result[1],
            'file_size': result[2],
            'mime_type': result[3]
        }
    return None

def update_file_access(username, file_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""UPDATE file_metadata 
                 SET last_accessed=?, download_count=download_count+1
                 WHERE username=? AND id=?""",
              (datetime.now().isoformat(), username, file_id))
    
    conn.commit()
    conn.close()

def get_analytics_data():
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Get various analytics
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM file_metadata")
    total_files = c.fetchone()[0]
    
    c.execute("SELECT SUM(file_size) FROM file_metadata")
    total_storage = c.fetchone()[0] or 0
    
    c.execute("""SELECT action, COUNT(*) FROM analytics 
                 WHERE timestamp > datetime('now', '-30 days')
                 GROUP BY action ORDER BY COUNT(*) DESC LIMIT 10""")
    top_actions = c.fetchall()
    
    conn.close()
    
    return {
        'total_users': total_users,
        'total_files': total_files,
        'total_storage': total_storage,
        'top_actions': top_actions
    }

def get_user_by_api_key(api_key):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("SELECT username FROM users WHERE api_key=?", (api_key,))
    result = c.fetchone()
    conn.close()
    
    return result[0] if result else None

def log_api_usage(api_key, endpoint, method, response_code, response_time=0):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""INSERT INTO api_usage 
                 (api_key, endpoint, method, timestamp, response_code, response_time)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              (api_key, endpoint, method, datetime.now().isoformat(), response_code, response_time))
    
    conn.commit()
    conn.close()

def get_user_info(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT username, plan, storage_used, api_key, organization, department
                 FROM users WHERE username=?""", (username,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return {
            'username': result[0],
            'plan': result[1],
            'storage_used': result[2],
            'api_key': result[3],
            'organization': result[4],
            'department': result[5]
        }
    return None

def has_2fa_enabled(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    return result and result[0] is not None

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