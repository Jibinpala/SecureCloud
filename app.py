from flask import Flask, render_template, request, redirect, session, flash, send_from_directory, url_for, jsonify, abort, Response
import os
import random
import string
import datetime
import secrets
import uuid
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import zipfile
import io
import json

# Core Modules
from config import DATABASE_PATH, UPLOAD_FOLDER, IS_VERCEL
from auth import init_db, register_user, verify_user, reset_password
from crypto import encrypt_file, decrypt_file
from admin import get_all_users, get_all_files
from security import security_manager, rate_limit
from mfa_manager import mfa_manager
from enhanced_security import enhanced_security, csrf_protect, rate_limit_enhanced
from database_manager import db_manager
from storage_manager import storage_manager
from performance_optimizer import (
    cache_manager, file_chunk_manager, async_task_manager, 
    performance_monitor, monitor_performance, cache_result
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "kryox_enterprise_secure_persistent_key_2026")
DB_PATH = DATABASE_PATH
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['WTF_CSRF_ENABLED'] = True

BASE_UPLOAD = UPLOAD_FOLDER
if not IS_VERCEL:
    os.makedirs(BASE_UPLOAD, exist_ok=True)

# App Configurations
DOCUMENT_TYPES = ['contract', 'invoice', 'report', 'policy', 'manual', 'other']
DEPARTMENTS = ['hr', 'finance', 'legal', 'it', 'operations', 'management']
STORAGE_QUOTAS = {
    'free': 500 * 1024 * 1024,      # 500MB
    'premium': 1024 * 1024 * 1024,  # 1GB
    'enterprise': 10 * 1024 * 1024 * 1024  # 10GB
}

def init_unified_db():
    """Consolidated database initialization using db_manager"""
    init_db()  # Base auth tables check
    
    # Professional and DMS columns for users (standard names across dialects)
    columns = [
        ("plan", "VARCHAR(20) DEFAULT 'free'"),
        ("storage_used", "BIGINT DEFAULT 0"),
        ("totp_secret", "TEXT"),
        ("mfa_enabled", "INTEGER DEFAULT 0"),
        ("suspended", "INTEGER DEFAULT 0")
    ]
    
    # We use db_manager.execute_query which handles the connection
    # For migration/init, we'll try standard SQL
    db_manager.execute_query("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            email TEXT
        )
    """)
    
    # Professional and DMS columns for users (standard names across dialects)
    columns = [
        ("plan", "TEXT DEFAULT 'free'"),
        ("storage_used", "BIGINT DEFAULT 0"),
        ("api_key", "TEXT"),
        ("organization", "TEXT"),
        ("department", "TEXT"),
        ("permissions", "TEXT DEFAULT 'read,write'"),
        ("totp_secret", "TEXT"),
        ("email", "TEXT"),
        ("email_hash", "TEXT"),
        ("mfa_enabled", "INTEGER DEFAULT 0"),
        ("suspended", "INTEGER DEFAULT 0"),
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until", "TEXT"),
        ("last_login", "TEXT")
    ]
    
    for col_name, col_def in columns:
        try:
            db_manager.execute_query(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
        except Exception:
            pass # Column likely already exists

    # DMS Tables Migration
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        username TEXT,
        filename TEXT,
        original_name TEXT,
        document_type TEXT,
        department TEXT,
        file_size BIGINT,
        mime_type TEXT,
        upload_date TEXT,
        last_modified TEXT,
        version INTEGER DEFAULT 1,
        status TEXT DEFAULT 'draft',
        tags TEXT,
        description TEXT,
        approval_required INTEGER DEFAULT 0,
        approved_by TEXT,
        approval_date TEXT,
        file_hash TEXT,
        download_count INTEGER DEFAULT 0
    )""")

    # Ensure all document columns exist (migration)
    doc_columns = [
        ("last_modified", "TEXT"),
        ("version", "INTEGER DEFAULT 1"),
        ("status", "TEXT DEFAULT 'draft'"),
        ("tags", "TEXT"),
        ("description", "TEXT"),
        ("approval_required", "INTEGER DEFAULT 0"),
        ("approved_by", "TEXT"),
        ("approval_date", "TEXT"),
        ("file_hash", "TEXT"),
        ("download_count", "INTEGER DEFAULT 0")
    ]
    
    for col_name, col_def in doc_columns:
        try:
            db_manager.execute_query(f"ALTER TABLE documents ADD COLUMN {col_name} {col_def}")
        except Exception:
            pass
    
    
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS document_versions (
        id SERIAL PRIMARY KEY,
        document_id INTEGER,
        version INTEGER,
        filename TEXT,
        uploaded_by TEXT,
        upload_date TEXT,
        changes_description TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")
    
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS approval_workflows (
        id SERIAL PRIMARY KEY,
        document_id INTEGER,
        approver TEXT,
        status TEXT DEFAULT 'pending',
        request_date TEXT,
        decision_date TEXT,
        comments TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")
    
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS shared_links (
        id SERIAL PRIMARY KEY,
        token TEXT UNIQUE,
        document_id INTEGER,
        expires_at TEXT,
        max_downloads INTEGER,
        current_downloads INTEGER DEFAULT 0,
        created_by TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")
    
    # User Sessions and Logs
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS security_logs (
        id SERIAL PRIMARY KEY,
        timestamp TEXT,
        username TEXT,
        ip_address TEXT,
        action TEXT,
        status TEXT,
        details TEXT
    )""")
    
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        username TEXT,
        session_id TEXT UNIQUE,
        ip_address TEXT,
        created_at TEXT,
        last_activity TEXT,
        is_active INTEGER DEFAULT 1
    )""")

    # Analytics
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS analytics (
        id SERIAL PRIMARY KEY,
        username TEXT,
        action TEXT,
        resource TEXT,
        timestamp TEXT,
        ip_address TEXT,
        user_agent TEXT,
        metadata TEXT
    )""")
    
    # Document access log
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS document_access (
        id SERIAL PRIMARY KEY,
        document_id INTEGER,
        username TEXT,
        action TEXT,
        timestamp TEXT,
        ip_address TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")

    # MFA Backup Codes
    db_manager.execute_query("""CREATE TABLE IF NOT EXISTS mfa_backup_codes (
        id SERIAL PRIMARY KEY,
        username TEXT,
        code_hash TEXT,
        used INTEGER DEFAULT 0,
        created_at TEXT
    )""")
    

# init_unified_db() call moved to __main__ for stability with reloader

# --- Helpers ---

def require_auth(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for('login'))
            if not security_manager.validate_session(session.get("user"), session.get("session_id")):
                for key in ['user', 'role', 'plan', 'session_id']:
                    session.pop(key, None)
                flash("Session expired. Please login again.")
                return redirect(url_for('login'))
            if role and session.get("role") != role:
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.context_processor
def inject_globals():
    return dict(
        csrf_token=enhanced_security.generate_csrf_token,
        now=datetime.now()
    )

# --- Routes ---

@app.route("/", methods=["GET", "POST"])
@rate_limit(max_attempts=50, window=300)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_input = request.form.get("captcha", "")
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        if captcha_input.upper() != session.get("captcha", "").upper():
            # CAPTCHA verification logic
            session.pop("captcha", None) # Force new captcha on next GET
            flash("Invalid captcha")
            return redirect(url_for('login'))
        
        if security_manager.is_account_locked(username):
            flash("Account is locked or suspended")
            return redirect(url_for('login'))
        
        # Modified logic for login and MFA check
        result = db_manager.execute_query(
            "SELECT username, password, role, mfa_enabled, plan FROM users WHERE username=?", 
            (username,), fetch_one=True
        )

        if result and check_password_hash(result['password'], password):
            # Check MFA
            if result.get('mfa_enabled'): # mfa_enabled
                session["mfa_pending_user"] = username
                session["mfa_pending_user_data"] = {
                    "role": result['role'],
                    "plan": result.get('plan', 'free')
                }
                return redirect(url_for('mfa_verify_challenge'))
            
            session_id = secrets.token_hex(32)
            session["user"] = username
            session["role"] = result['role']
            session["plan"] = result.get('plan', 'free')
            session["session_id"] = session_id
            session.permanent = True
            
            security_manager.record_successful_login(username, ip_address)
            security_manager.create_session(username, session_id, ip_address)
            
            if session["role"] == "admin":
                return redirect(url_for('dashboard'))
            return redirect(url_for('dashboard'))
        else:
            security_manager.record_failed_attempt(username, ip_address)
            flash("Invalid credentials")
            return redirect(url_for('login'))
            
    # Only generate new captcha if one doesn't exist
    if "captcha" not in session:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        session["captcha"] = ''.join(random.choices(alphabet, k=6))
        
    return render_template("login.html", captcha=session["captcha"])

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        terms_accepted = request.form.get("terms")
        ip_address = request.remote_addr
        
        # Check Compliance Checkbox
        if not terms_accepted:
            flash("You must accept the Privacy Policy and Protocol Terms to register.")
            return redirect(url_for('register'))
        
        # Validation
        is_strong, msg = security_manager.validate_password_strength(password)
        if not is_strong:
            flash(msg)
            return redirect(url_for('register'))
            
        try:
            register_user(username, password, email)
            security_manager.log_security_event(username, ip_address, "REGISTRATION", "SUCCESS", f"User registered with email {email}")
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except Exception as e:
            # Handle unique constraint violations for both SQLite and Postgres
            error_msg = str(e).lower()
            if "unique" in error_msg or "already exists" in error_msg:
                flash("Username already exists")
            else:
                flash(f"Registration error: {e}")
            return redirect(url_for('register'))
            
    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "")
        ip_address = request.remote_addr
        
        # Validation
        is_strong, msg = security_manager.validate_password_strength(new_password)
        if not is_strong:
            flash(msg)
            return redirect(url_for('forgot_password'))
            
        if reset_password(username, email, new_password):
            security_manager.log_security_event(username, ip_address, "PASSWORD_RESET", "SUCCESS", "Password reset successful")
            flash("Password updated successfully! Please login.", "success")
            return redirect(url_for('login'))
        else:
            security_manager.log_security_event(username, ip_address, "PASSWORD_RESET", "FAILURE", "Invalid username or email combination")
            flash("Invalid username or email combination")
            return redirect(url_for('forgot_password'))
            
    return render_template("forgot_password.html")

@app.route("/privacy")
def privacy_policy():
    try:
        with open("PRIVACY.md", "r", encoding='utf-8') as f:
            content = f.read()
        return render_template("security_timeline.html", logs=[], custom_content=content, 
                               title="Privacy Protocol", subtitle="Legal Compliance & Data Protection")
    except:
        return "Privacy Policy not found. Please contact administrator.", 404

@app.route("/settings")
@require_auth()
def settings():
    user_info = get_user_info(session["user"])
    return render_template("settings.html", user=user_info)

@app.route("/update_profile", methods=["POST"])
@require_auth()
@csrf_protect
def update_profile():
    org = request.form.get("organization", "").strip()
    dept = request.form.get("department", "").strip()
    username = session["user"]
    
    db_manager.execute_query(
        "UPDATE users SET organization=?, department=? WHERE username=?",
        (org, dept, username)
    )
    
    security_manager.log_security_event(username, request.remote_addr, "PROFILE_UPDATE", "SUCCESS", f"Updated org: {org}, dept: {dept}")
    flash("Profile updated successfully", "success")
    return redirect(url_for('settings'))

@app.route("/change_password", methods=["POST"])
@require_auth()
@csrf_protect
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    username = session["user"]
    
    row = db_manager.execute_query("SELECT password FROM users WHERE username=?", (username,), fetch_one=True)
    
    if row and check_password_hash(row['password'], current_pw):
        is_strong, msg = security_manager.validate_password_strength(new_pw)
        if not is_strong:
            flash(msg)
            return redirect(url_for('settings'))
            
        db_manager.execute_query(
            "UPDATE users SET password=? WHERE username=?",
            (generate_password_hash(new_pw), username)
        )
        security_manager.log_security_event(username, request.remote_addr, "PASSWORD_CHANGE", "SUCCESS", "User changed password via settings")
        flash("Password updated successfully", "success")
    else:
        flash("Invalid current password")
        
    return redirect(url_for('settings'))

@app.route("/generate_api_key", methods=["POST"])
@require_auth()
@csrf_protect
def generate_api_key():
    username = session["user"]
    new_key = f"kx_{secrets.token_urlsafe(32)}"
    
    db_manager.execute_query(
        "UPDATE users SET api_key=? WHERE username=?",
        (new_key, username)
    )
    
    security_manager.log_security_event(username, request.remote_addr, "API_KEY_GENERATE", "SUCCESS", "Regenerated API key")
    flash("New API key generated successfully", "success")
    return redirect(url_for('settings'))

@app.route("/setup-2fa")
@require_auth()
def setup_2fa():
    return "2FA Setup coming soon."

@app.route("/verify-2fa")
def verify_2fa():
    return "2FA Verification coming soon."

@app.route("/otp")
def otp():
    return "OTP Verification coming soon."

@app.route("/mfa/setup")
@require_auth()
def mfa_setup():
    username = session["user"]
    # Check if already enabled
    row = db_manager.execute_query("SELECT totp_secret, mfa_enabled FROM users WHERE username=?", (username,), fetch_one=True)
    
    if row and row.get('mfa_enabled'):
        flash("MFA is already enabled.")
        return redirect(url_for('dashboard'))
    
    secret = row['totp_secret'] if row and row.get('totp_secret') else mfa_manager.generate_secret()
    if not row or not row.get('totp_secret'):
        db_manager.execute_query("UPDATE users SET totp_secret=? WHERE username=?", (secret, username))
    
    uri = mfa_manager.get_provisioning_uri(username, secret)
    qr_code = mfa_manager.generate_qr_base64(uri)
    
    return render_template("mfa_setup.html", qr_code=qr_code, secret=secret)

@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify_challenge():
    if "mfa_pending_user" not in session:
        return redirect(url_for('login'))
        
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        username = session["mfa_pending_user"]
        
        row = db_manager.execute_query("SELECT totp_secret FROM users WHERE username=?", (username,), fetch_one=True)
        
        if row and mfa_manager.verify_token(row['totp_secret'], token):
            # Success! Complete login
            user_data = session.pop("mfa_pending_user_data")
            session_id = secrets.token_hex(32)
            session["user"] = username
            session["role"] = user_data["role"]
            session["plan"] = user_data["plan"]
            session["session_id"] = session_id
            session.permanent = True
            session.pop("mfa_pending_user")
            
            security_manager.record_successful_login(username, request.remote_addr)
            security_manager.create_session(username, session_id, request.remote_addr)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid MFA code. Please try again.")
            
    return render_template("mfa_verify.html")

@app.route("/mfa/verify-backup", methods=["POST"])
def mfa_verify_backup():
    if "mfa_pending_user" not in session:
        return redirect(url_for('login'))
        
    backup_code = request.form.get("backup_code", "").strip().upper()
    username = session["mfa_pending_user"]
    
    # Hash and check against DB
    code_hash = mfa_manager.hash_code(backup_code)
    
    row = db_manager.execute_query("SELECT id FROM mfa_backup_codes WHERE username=? AND code_hash=? AND used=0", (username, code_hash), fetch_one=True)
    
    if row:
        # Mark as used
        db_manager.execute_query("UPDATE mfa_backup_codes SET used=1 WHERE id=?", (row['id'],))
        
        # Success! Complete login
        user_data = session.pop("mfa_pending_user_data")
        session_id = secrets.token_hex(32)
        session["user"] = username
        session["role"] = user_data["role"]
        session["plan"] = user_data["plan"]
        session["session_id"] = session_id
        session.permanent = True
        session.pop("mfa_pending_user")
        
        security_manager.record_successful_login(username, request.remote_addr)
        security_manager.create_session(username, session_id, request.remote_addr)
        flash("Backup code verified. Please regenerate your codes soon.", "success")
        return redirect(url_for('dashboard'))
    else:
        conn.close()
        flash("Invalid or already used backup code.")
        return redirect(url_for('mfa_verify_challenge'))

@app.route("/mfa/generate-backup-codes", methods=["POST"])
@require_auth()
@csrf_protect
def mfa_generate_backup_codes():
    username = session["user"]
    codes = mfa_manager.generate_backup_codes(8)
    
    # Delete old codes
    db_manager.execute_query("DELETE FROM mfa_backup_codes WHERE username=?", (username,))
    
    # Insert new hashed codes
    for code in codes:
        code_hash = mfa_manager.hash_code(code)
        db_manager.execute_query("INSERT INTO mfa_backup_codes (username, code_hash, created_at) VALUES (?, ?, ?)", 
                  (username, code_hash, datetime.now().isoformat()))
    
    security_manager.log_security_event(username, request.remote_addr, "MFA_BACKUP_CODES_GENERATED", "SUCCESS", "Generated 8 new backup codes")
    return jsonify({"status": "success", "codes": codes})

def update_storage_usage(username, bytes_added):
    db_manager.execute_query(
        "UPDATE users SET storage_used = COALESCE(storage_used, 0) + ? WHERE username=?",
        (bytes_added, username)
    )

@app.route("/mfa/revoke-backup-codes", methods=["POST"])
@require_auth()
@csrf_protect
def mfa_revoke_backup_codes():
    username = session["user"]
    db_manager.execute_query("DELETE FROM mfa_backup_codes WHERE username=?", (username,))
    security_manager.log_security_event(username, request.remote_addr, "MFA_BACKUP_CODES_REVOKED", "SUCCESS", "Revoked all backup codes")
    return jsonify({"status": "success", "message": "All recovery protocols revoked"})

@app.route("/mfa/enable", methods=["POST"])
@require_auth()
@csrf_protect
def mfa_enable():
    token = request.form.get("token", "").strip()
    username = session["user"]
    
    row = db_manager.execute_query("SELECT totp_secret FROM users WHERE username=?", (username,), fetch_one=True)
    secret = row['totp_secret'] if row else None
    
    if secret and mfa_manager.verify_token(secret, token):
        db_manager.execute_query("UPDATE users SET mfa_enabled=1 WHERE username=?", (username,))
        security_manager.log_security_event(username, request.remote_addr, "MFA_ENABLED", "SUCCESS", "MFA enabled successfully")
        flash("MFA enabled successfully!", "success")
        return redirect(url_for('dashboard'))
    
    conn.close()
    flash("Invalid verification code. MFA not enabled.")
    return redirect(url_for('mfa_setup'))

@app.route("/dashboard")
@require_auth()
def dashboard():
    username = session["user"]
    user_info = get_user_info(username)
    
    if session["role"] == "admin":
        # Admin gets full DMS view in unified dashboard
        dept = user_info.get("department", "general")
        return render_template("dms_dashboard.html", 
                             documents=get_user_documents(username),
                             department_docs=get_department_documents(dept),
                             pending_approvals=get_pending_approvals(username),
                             document_types=DOCUMENT_TYPES,
                             departments=DEPARTMENTS)
    
    # Regular users get the Professional dashboard
    files = get_user_files_with_metadata(username)
    stats = get_user_statistics(username)
    return render_template("professional_dashboard.html", files=files, stats=stats)

@app.route("/security-timeline")
@require_auth()
def security_timeline():
    username = session["user"]
    logs = security_manager.get_user_audit_log(username)
    return render_template("security_timeline.html", logs=logs)

@app.route("/upload", methods=["POST"])
@require_auth()
@csrf_protect
def upload():
    files = request.files.getlist("file")
    ip_address = request.remote_addr
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    if not IS_VERCEL:
        os.makedirs(user_folder, exist_ok=True)
    
    upload_count = 0
    try:
        for file in files:
            if file and file.filename:
                content = file.read()
                # Security scan
                is_valid, msg = enhanced_security.validate_file(file, content)
                if not is_valid:
                    security_manager.log_security_event(session["user"], ip_address, "FILE_UPLOAD_BLOCKED", "FAILED", f"Blocked: {file.filename} - {msg}")
                    flash(msg)
                    continue
                    
                file_id = str(uuid.uuid4())
                encrypted_name = f"{file_id}.enc"
                encrypted_data = encrypt_file(content)
                
                # Use storage_manager for persistence
                remote_path = f"{session['user']}/{encrypted_name}"
                if storage_manager.upload_file(encrypted_data, remote_path):
                    # Update storage used
                    update_storage_usage(session["user"], len(encrypted_data))
                    
                # Metadata & Versioning check
                existing = db_manager.execute_query(
                    "SELECT id, version, filename FROM documents WHERE username=? AND original_name=?",
                    (session["user"], file.filename), fetch_one=True
                )
                
                new_version_num = 1
                if existing:
                    doc_id, current_ver, old_filename = existing
                    new_version_num = current_ver + 1
                    
                    # Move current to versions table
                    db_manager.execute_query(
                        "INSERT INTO document_versions (document_id, version, filename, uploaded_by, upload_date, changes_description) VALUES (?,?,?,?,?,?)",
                        (doc_id, current_ver, old_filename, session["user"], datetime.now().isoformat(), "Auto-version check")
                    )
                    
                    # Update main document
                    db_manager.execute_query(
                        "UPDATE documents SET filename=?, version=?, file_size=?, mime_type=?, upload_date=?, file_hash=? WHERE id=?",
                        (encrypted_name, new_version_num, len(encrypted_data), file.content_type, datetime.now().isoformat(), enhanced_security.calculate_file_hash(content), doc_id)
                    )
                else:
                    store_document_metadata(
                        session["user"], encrypted_name, file.filename,
                        request.form.get("document_type", "file"), 
                        request.form.get("department", session.get("dept", "personal")), 
                        len(encrypted_data),
                        file.content_type,
                        request.form.get("desc", ""),
                        False,
                        enhanced_security.calculate_file_hash(content)
                    )
                
                upload_count += 1
                security_manager.log_security_event(session["user"], ip_address, "FILE_UPLOAD", "SUCCESS", f"Uploaded: {file.filename} (v{new_version_num})")
                
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"status": "success", "message": f"{upload_count} files uploaded successfully"})
            
        flash(f"{upload_count} files uploaded successfully")
        return redirect("/dashboard")
    except Exception as e:
        import traceback
        error_msg = f"UPLOAD_CRASH: {str(e)}\n{traceback.format_exc()}"
        security_manager.log_security_event(session.get("user", "system"), ip_address, "FILE_UPLOAD_CRASH", "ERROR", error_msg[:500])
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"status": "error", "message": f"Server failure: {str(e)}"}), 500
        flash(f"Upload failed: {str(e)}")
        return redirect("/dashboard")
    return redirect("/dashboard")

@app.route("/download/<int:file_id>")
@require_auth()
def download(file_id):
    info = get_file_metadata(session["user"], file_id)
    if not info: abort(404)
    
    remote_path = f"{session['user']}/{info['filename']}"
    encrypted_data = storage_manager.download_file(remote_path)
    if not encrypted_data: abort(404)
    
    decrypted_data = decrypt_file(encrypted_data)
    
    increment_download_count(file_id)
    security_manager.log_security_event(session["user"], request.remote_addr, "FILE_DOWNLOAD", "SUCCESS", f"Downloaded: {info['original_name']}")
    
    return Response(
        decrypted_data,
        mimetype=info['mime_type'],
        headers={"Content-disposition": f"attachment; filename={info['original_name']}"}
    )

@app.route("/preview/<int:file_id>")
@require_auth()
def preview(file_id):
    info = get_file_metadata(session["user"], file_id)
    if not info: abort(404)
    
    path = os.path.join(BASE_UPLOAD, session["user"], info['filename'])
    if not os.path.exists(path): abort(404)
    
    try:
        with open(path, 'rb') as f:
            decrypted = decrypt_file(f.read())
        
        mime = info['mime_type'] or 'application/octet-stream'
        if mime.startswith(('text/', 'image/', 'application/pdf')) or mime == 'application/json':
            return Response(decrypted, mimetype=mime)
        return jsonify({"error": "Preview not available for this type"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/share/<int:file_id>", methods=["POST"])
@require_auth()
@csrf_protect
def share_file(file_id):
    hours = int(request.form.get("hours", 24))
    max_dloads = int(request.form.get("max_downloads", 10))
    
    info = get_file_metadata(session["user"], file_id)
    if not info:
        return jsonify({"status": "error", "message": "File not found"}), 404
    
    token = secrets.token_urlsafe(16)
    expires_at = (datetime.now() + timedelta(hours=hours)).isoformat()
    
    db_manager.execute_query(
        "INSERT INTO shared_links (file_id, token, expires_at, max_downloads, created_by) VALUES (?,?,?,?,?)",
        (file_id, token, expires_at, max_dloads, session["user"])
    )
    
    share_url = url_for('public_access', token=token, _external=True)
    security_manager.log_security_event(session["user"], request.remote_addr, "FILE_SHARE", "SUCCESS", f"Created share link for: {info['original_name']}")
    
    return jsonify({"status": "success", "share_url": share_url})

@app.route("/s/<token>")
def public_access(token):
    link = db_manager.execute_query(
        "SELECT sl.*, d.filename, d.original_name, d.mimetype as mime_type FROM shared_links sl JOIN documents d ON sl.document_id = d.id WHERE sl.token=?",
        (token,), fetch_one=True
    )
    
    if not link:
        abort(404, description="Link not found")
    
    # Check expiration
    if datetime.now() > datetime.fromisoformat(link['expires_at']): # expires_at
        abort(410, description="Link expired (time)")
        
    # Check downloads
    if link['current_downloads'] >= link['max_downloads']: # current vs max
        abort(410, description="Link expired (download limit reached)")
        
    # Update count
    db_manager.execute_query("UPDATE shared_links SET current_downloads = current_downloads + 1 WHERE token=?", (token,))
    
    # Log public access
    security_manager.log_security_event(link['created_by'], request.remote_addr, "PUBLIC_ACCESS", "SUCCESS", f"Public download: {link['original_name']}")
    
    remote_path = f"{link['created_by']}/{link['filename']}"
    encrypted_data = storage_manager.download_file(remote_path)
    if not encrypted_data: abort(404)
    
    decrypted_data = decrypt_file(encrypted_data)
    
    return Response(
        decrypted_data,
        mimetype=link['mime_type'],
        headers={"Content-disposition": f"attachment; filename={link['original_name']}"}
    )

@app.route("/versions/<int:file_id>")
@require_auth()
def get_versions(file_id):
    info = get_file_metadata(session["user"], file_id)
    if not info:
        return jsonify({"status": "error", "message": "File not found"}), 404
        
    versions = db_manager.execute_query(
        "SELECT id, version, upload_date, changes_description FROM document_versions WHERE document_id=? ORDER BY version DESC",
        (file_id,), fetch_all=True
    )
    
    # Convert to list of dicts
    version_list = [{"id": v['id'], "version": v['version'], "date": v['upload_date'], "desc": v['changes_description']} for v in versions]
    return jsonify({"status": "success", "versions": version_list, "current_version": info['version']})

@app.route("/rollback/<int:version_id>", methods=["POST"])
@require_auth()
@csrf_protect
def rollback_version(version_id):
    # Fetch the old version info
    old_version = db_manager.execute_query(
        "SELECT document_id, version, filename FROM document_versions WHERE id=?",
        (version_id,), fetch_one=True
    )
    
    if not old_version:
        return jsonify({"status": "error", "message": "Version not found"}), 404
        
    doc_id = old_version['document_id']
    v_num = old_version['version']
    old_filename = old_version['filename']
    
    # Fetch current main document
    current = db_manager.execute_query(
        "SELECT filename, version, original_name FROM documents WHERE id=? AND username=?",
        (doc_id, session["user"]), fetch_one=True
    )
    
    if not current:
        return jsonify({"status": "error", "message": "Access denied"}), 403
        
    curr_filename = current['filename']
    curr_ver = current['version']
    orig_name = current['original_name']
    
    # Swap: move current to versions, restore old to main
    # 1. Archive current
    db_manager.execute_query(
        "INSERT INTO document_versions (document_id, version, filename, uploaded_by, upload_date, changes_description) VALUES (?,?,?,?,?,?)",
        (doc_id, curr_ver, curr_filename, session["user"], datetime.now().isoformat(), f"Rollback to v{v_num}")
    )
    
    # 2. Restore old
    db_manager.execute_query(
        "UPDATE documents SET filename=?, version=? WHERE id=?",
        (old_filename, curr_ver + 1, doc_id)
    )
    
    # 3. Remove the old version entry since it's now main (or keep it if you want full history)
    db_manager.execute_query("DELETE FROM document_versions WHERE id=?", (version_id,))
    
    security_manager.log_security_event(session["user"], request.remote_addr, "FILE_ROLLBACK", "SUCCESS", f"Rolled back {orig_name} to v{v_num}")
    
    return jsonify({"status": "success", "message": f"Rolled back to version {v_num}"})

@app.route("/delete/<int:file_id>", methods=["POST"])
@require_auth()
@csrf_protect
def delete_file_handler(file_id):
    info = get_file_metadata(session["user"], file_id)
    if not info:
        return jsonify({"status": "error", "message": "File not found"}), 404
    
    # Soft delete: Update status to 'deleted'
    db_manager.execute_query("UPDATE documents SET status='deleted' WHERE id=? AND username=?", (file_id, session["user"]))
    
    security_manager.log_security_event(session["user"], request.remote_addr, "FILE_TRASH", "SUCCESS", f"Moved to trash: {info['original_name']}")
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"status": "success", "message": "File moved to trash"})
    
    flash("File moved to trash")
    return redirect("/dashboard")

@app.route("/bulk/delete", methods=["POST"])
@require_auth()
@csrf_protect
def bulk_delete_handler():
    file_ids = json.loads(request.form.get("file_ids", "[]"))
    username = session["user"]
    
    for fid in file_ids:
        db_manager.execute_query("UPDATE documents SET status='deleted' WHERE id=? AND username=?", (fid, username))
        
    security_manager.log_security_event(username, request.remote_addr, "BULK_TRASH", "SUCCESS", f"Moved {len(file_ids)} files to trash")
    return jsonify({"status": "success", "message": f"{len(file_ids)} files moved to trash"})

@app.route("/bulk/download")
@require_auth()
def bulk_download_handler():
    file_ids = request.args.get("ids", "").split(",")
    username = session["user"]
    
    if not file_ids or file_ids == ['']:
        return "No files selected", 400
        
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for fid in file_ids:
            info = get_file_metadata(username, int(fid))
            if info:
                remote_path = f"{username}/{info['filename']}"
                encrypted_data = storage_manager.download_file(remote_path)
                if encrypted_data:
                    decrypted_data = decrypt_file(encrypted_data)
                    zip_file.writestr(info['original_name'], decrypted_data)
    
    zip_buffer.seek(0)
    return Response(
        zip_buffer.getvalue(),
        mimetype="application/zip",
        headers={"Content-disposition": f"attachment; filename=kryox_bulk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"}
    )

@app.route("/trash")
@require_auth()
def trash_view():
    username = session["user"]
    files = db_manager.execute_query(
        "SELECT id, original_name, file_size, upload_date FROM documents WHERE username=? AND status='deleted'",
        (username,), fetch_all=True
    )
    # Convert tuples to dicts for template
    trash_files = [{"id": f['id'], "name": f['original_name'], "size": f['file_size'], "date": f['upload_date']} for f in files]
    return render_template("trash.html", files=trash_files)

@app.route("/trash/restore/<int:file_id>", methods=["POST"])
@require_auth()
@csrf_protect
def restore_file(file_id):
    db_manager.execute_query("UPDATE documents SET status='active' WHERE id=? AND username=?", (file_id, session["user"]))
    security_manager.log_security_event(session["user"], request.remote_addr, "FILE_RESTORE", "SUCCESS", f"Restored file ID: {file_id}")
    return jsonify({"status": "success", "message": "File restored"})

@app.route("/trash/purge/<int:file_id>", methods=["POST"])
@require_auth()
@csrf_protect
def purge_file(file_id):
    info = get_file_metadata(session["user"], file_id)
    if not info:
        return jsonify({"status": "error", "message": "File not found"}), 404
        
    # 1. Delete actual file from storage
    remote_path = f"{session['user']}/{info['filename']}"
    storage_manager.delete_file(remote_path)
        
    # 2. Delete versions from storage
    versions = db_manager.execute_query("SELECT filename FROM document_versions WHERE document_id=?", (file_id,), fetch_all=True)
    for v in versions:
        v_remote_path = f"{session['user']}/{v['filename']}"
        storage_manager.delete_file(v_remote_path)
            
    # 3. Purge DB records
    db_manager.execute_query("DELETE FROM documents WHERE id=?", (file_id,))
    db_manager.execute_query("DELETE FROM document_versions WHERE document_id=?", (file_id,))
    
    security_manager.log_security_event(session["user"], request.remote_addr, "FILE_PURGE", "SUCCESS", f"Permanently deleted: {info['original_name']}")
    return jsonify({"status": "success", "message": "File permanently deleted"})

@app.route("/share/<int:file_id>")
@require_auth()
def share(file_id):
    info = get_file_metadata(session["user"], file_id)
    if not info: abort(404)
    
    share_url = url_for('download', file_id=file_id, _external=True)
    expires = (datetime.now() + timedelta(hours=1)).isoformat() + 'Z'
    return jsonify({'share_url': share_url, 'expires': expires})


@app.route("/admin")
@require_auth(role="admin")
def admin_panel():
    return render_template("admin_dashboard.html", users=get_all_users(), files=get_all_files())

@app.route("/admin/security")
@require_auth(role="admin")
def admin_security_route():
    logs = security_manager.get_security_logs(200)
    return render_template("security_dashboard.html", logs=logs)

@app.route("/admin/users")
@require_auth(role="admin")
def admin_users_route():
    users = get_all_users()
    user_status = {}
    for u in users:
        username = u['username']
        user_status[username] = {
            'suspended': security_manager.is_account_suspended(username),
            'locked': security_manager.is_account_locked(username)
        }
    return render_template("admin_users.html", users=users, user_status=user_status)

@app.route("/admin/files")
@require_auth(role="admin")
def admin_files_route():
    return render_template("admin_files.html", files=get_all_files())

@app.route("/admin/suspend/<username>")
@require_auth(role="admin")
def admin_suspend(username):
    security_manager.suspend_account(username)
    flash(f"Account {username} suspended")
    return redirect("/admin/users")

@app.route("/admin/unsuspend/<username>")
@require_auth(role="admin")
def admin_unsuspend(username):
    security_manager.unsuspend_account(username)
    flash(f"Account {username} unsuspended")
    return redirect("/admin/users")

@app.route("/admin/unlock/<username>")
@require_auth(role="admin")
def admin_unlock(username):
    security_manager.unlock_account(username)
    flash(f"Account {username} unlocked")
    return redirect("/admin/users")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# --- Data Helpers (Unified) ---

def update_storage_usage(username, size_change):
    db_manager.execute_query(
        "UPDATE users SET storage_used = COALESCE(storage_used, 0) + ? WHERE username=?",
        (size_change, username)
    )

def increment_download_count(file_id):
    db_manager.execute_query(
        "UPDATE documents SET download_count = download_count + 1 WHERE id=?",
        (file_id,)
    )

def get_user_info(username):
    row = db_manager.execute_query("SELECT * FROM users WHERE username=?", (username,), fetch_one=True)
    if row:
        d = dict(row)
        # Ensure default values for template robustness
        d['plan'] = d.get('plan') or 'free'
        d['storage_used'] = d.get('storage_used') or 0
        return d
    return {'username': username, 'plan': 'free', 'storage_used': 0}

def get_user_files_with_metadata(username):
    with db_manager.get_connection() as (conn, cursor):
        cursor.execute("SELECT * FROM documents WHERE username=? AND status='active' ORDER BY upload_date DESC", (username,))
        return [dict(row) for row in cursor.fetchall()]

def get_user_statistics(username):
    info = get_user_info(username)
    used = info.get('storage_used', 0)
    quota = STORAGE_QUOTAS.get(info.get('plan', 'free'), STORAGE_QUOTAS['free'])
    return {
        'storage_used': used,
        'storage_quota': quota,
        'storage_percentage': (used / quota) * 100 if quota > 0 else 0,
        'file_count': len(get_user_files_with_metadata(username))
    }

def store_document_metadata(username, filename, original_name, doc_type, dept, size, mime, desc, apprv, fhash):
    db_manager.execute_query(
        "INSERT INTO documents (username, filename, original_name, document_type, department, file_size, mime_type, upload_date, status, description, approval_required, file_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (username, filename, original_name, doc_type, dept, size, mime, datetime.now().isoformat(), 'active', desc, apprv, fhash)
    )

def get_file_metadata(username, file_id):
    return db_manager.execute_query("SELECT * FROM documents WHERE username=? AND id=?", (username, file_id), fetch_one=True)

def get_user_documents(username):
    rows = db_manager.execute_query("SELECT * FROM documents WHERE username=? AND status='active' ORDER BY upload_date DESC", (username,), fetch_all=True)
    return [dict(row) for row in rows]

def get_pending_approvals(username):
    rows = db_manager.execute_query("""
        SELECT d.*, aw.status as approval_status, aw.id as workflow_id 
        FROM documents d 
        JOIN approval_workflows aw ON d.id = aw.document_id 
        WHERE aw.approver=? AND aw.status='pending'""", (username,), fetch_all=True)
    return [dict(row) for row in rows]

def get_department_documents(dept):
    rows = db_manager.execute_query("""
        SELECT * FROM documents 
        WHERE department=? AND status='active' 
        ORDER BY upload_date DESC""", (dept,), fetch_all=True)
    return [dict(row) for row in rows]

@app.route("/search")
@require_auth()
def search_documents():
    query = request.args.get("q", "")
    doc_type = request.args.get("type", "")
    dept = request.args.get("dept", "")
    
    sql = "SELECT * FROM documents WHERE status='active'"
    params = []
    
    if query:
        sql += " AND (original_name LIKE ? OR description LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])
    if doc_type:
        sql += " AND document_type = ?"
        params.append(doc_type)
    if dept:
        sql += " AND department = ?"
        params.append(dept)
        
    rows = db_manager.execute_query(sql, tuple(params), fetch_all=True)
    return jsonify([dict(row) for row in rows])

@app.route("/approve/<int:workflow_id>", methods=["POST"])
@require_auth()
def approve_document(workflow_id):
    decision = request.form.get("decision", "approved")
    comments = request.form.get("comments", "")
    
    # Update workflow
    db_manager.execute_query("""
        UPDATE approval_workflows 
        SET status=?, comments=?, decision_date=? 
        WHERE id=? AND approver=?""", 
        (decision, comments, datetime.now().isoformat(), workflow_id, session["user"]))
        
    # If approved, update document status
    if decision == "approved":
        db_manager.execute_query("""
            UPDATE documents SET status='active', approved_by=?, approval_date=? 
            WHERE id = (SELECT document_id FROM approval_workflows WHERE id=?)""",
            (session["user"], datetime.now().isoformat(), workflow_id))
    else:
        db_manager.execute_query("""
            UPDATE documents SET status='rejected', approved_by=?, approval_date=? 
            WHERE id = (SELECT document_id FROM approval_workflows WHERE id=?)""",
            (session["user"], datetime.now().isoformat(), workflow_id))
            
    return jsonify({"status": "success"})

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# @app.errorhandler(500)
# def internal_server_error(e):
#     return render_template('500.html'), 500

if __name__ == "__main__":
    init_unified_db()
    print("SecureCloud is initializing on http://127.0.0.1:5000")
    # Enable debug but disable reloader to avoid Windows restart loop
    app.run(debug=True, use_reloader=False, host='127.0.0.1', port=5000)
