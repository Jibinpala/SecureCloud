from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file, Response
from auth import init_db, register_user, verify_user
from crypto import encrypt_file, decrypt_file
from admin import get_all_users, get_all_files
from security import security_manager, rate_limit
from enhanced_security import enhanced_security, csrf_protect, rate_limit_enhanced
from database_manager import db_manager
from backup_compliance import backup_manager, compliance_manager
from performance_optimizer import cache_manager, file_chunk_manager, async_task_manager, performance_monitor, monitor_performance, cache_result
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
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# Add CSRF token to template context
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=enhanced_security.generate_csrf_token)

init_db()

BASE_UPLOAD = "encrypted_files/users"
os.makedirs(BASE_UPLOAD, exist_ok=True)

# DMS Configuration
DOCUMENT_TYPES = ['contract', 'invoice', 'report', 'policy', 'manual', 'other']
APPROVAL_STATUSES = ['draft', 'pending', 'approved', 'rejected', 'archived']
DEPARTMENTS = ['hr', 'finance', 'legal', 'it', 'operations', 'management']

def init_dms_db():
    """Initialize DMS database tables"""
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Add DMS columns to users
    try:
        c.execute("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'")
        c.execute("ALTER TABLE users ADD COLUMN storage_used INTEGER DEFAULT 0")
        c.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
        c.execute("ALTER TABLE users ADD COLUMN organization TEXT")
        c.execute("ALTER TABLE users ADD COLUMN department TEXT")
        c.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT 'read,write'")
    except sqlite3.OperationalError:
        pass
    
    # Document metadata table
    c.execute("""CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        filename TEXT,
        original_name TEXT,
        document_type TEXT,
        department TEXT,
        file_size INTEGER,
        mime_type TEXT,
        upload_date TEXT,
        last_modified TEXT,
        version INTEGER DEFAULT 1,
        status TEXT DEFAULT 'draft',
        tags TEXT,
        description TEXT,
        approval_required BOOLEAN DEFAULT 0,
        approved_by TEXT,
        approval_date TEXT
    )""")
    
    # Document versions table
    c.execute("""CREATE TABLE IF NOT EXISTS document_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        version INTEGER,
        filename TEXT,
        uploaded_by TEXT,
        upload_date TEXT,
        changes_description TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")
    
    # Approval workflows table
    c.execute("""CREATE TABLE IF NOT EXISTS approval_workflows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        approver TEXT,
        status TEXT DEFAULT 'pending',
        comments TEXT,
        created_date TEXT,
        decision_date TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")
    
    # Document access log
    c.execute("""CREATE TABLE IF NOT EXISTS document_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        username TEXT,
        action TEXT,
        timestamp TEXT,
        ip_address TEXT,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    )""")
    
    conn.commit()
    conn.close()

init_dms_db()

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

def check_document_permission(username, document_id, action='read'):
    """Check if user has permission to access document"""
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Get document and user info
    c.execute("""SELECT d.username, d.department, u.department, u.permissions 
                 FROM documents d, users u 
                 WHERE d.id=? AND u.username=?""", (document_id, username))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return False
    
    doc_owner, doc_dept, user_dept, user_perms = result
    permissions = user_perms.split(',') if user_perms else []
    
    # Owner has full access
    if doc_owner == username:
        return True
    
    # Same department access
    if doc_dept == user_dept and action in permissions:
        return True
    
    # Admin access
    if 'admin' in permissions:
        return True
    
    return False

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

@app.route("/dashboard")
@require_auth()
def dashboard():
    if session.get("role") == "admin":
        # Admin gets DMS interface
        user_documents = get_user_documents(session["user"])
        pending_approvals = get_pending_approvals(session["user"])
        department_docs = get_department_documents(session["user"])
        
        return render_template("dms_dashboard.html", 
                             documents=user_documents,
                             pending_approvals=pending_approvals,
                             department_docs=department_docs,
                             document_types=DOCUMENT_TYPES,
                             departments=DEPARTMENTS)
    else:
        # Regular users get secure storage interface
        user_files = get_user_files_with_metadata(session["user"])
        user_stats = get_user_statistics(session["user"])
        
        return render_template("professional_dashboard.html", 
                             files=user_files, 
                             stats=user_stats)

@app.route("/upload", methods=["POST"])
@require_auth()
@csrf_protect
@rate_limit_enhanced(max_requests=50, window=3600)
@monitor_performance("file_upload")
def upload_document():
    if session.get("role") == "admin":
        # Admin document upload with DMS features
        uploaded_files = request.files.getlist("file")
        document_type = request.form.get("document_type", "other")
        department = request.form.get("department", "")
        description = request.form.get("description", "")
        approval_required = request.form.get("approval_required") == "on"
        
        user_folder = os.path.join(BASE_UPLOAD, session["user"])
        os.makedirs(user_folder, exist_ok=True)
        
        success_count = 0
        
        for file in uploaded_files:
            if file and file.filename:
                try:
                    # Enhanced file validation
                    file_content = file.read()
                    file.seek(0)
                    
                    is_valid, validation_message = enhanced_security.validate_file(file, file_content)
                    if not is_valid:
                        flash(f"File {file.filename}: {validation_message}")
                        continue
                    
                    # Malware scanning
                    is_clean, scan_message = enhanced_security.scan_for_malware(file_content)
                    if not is_clean:
                        flash(f"File {file.filename}: {scan_message}")
                        continue
                    
                    file_id = str(uuid.uuid4())
                    encrypted_filename = f"{file_id}.enc"
                    
                    # Use chunked upload for large files
                    encrypted = encrypt_file(file_content)
                    file_path = os.path.join(user_folder, encrypted_filename)
                    
                    file_chunk_manager.upload_chunked_file(file_path, encrypted)
                    
                    # Calculate file hash for integrity
                    file_hash = enhanced_security.calculate_file_hash(file_content)
                    
                    # Store document metadata with hash
                    doc_id = store_document_metadata(
                        session["user"], encrypted_filename, file.filename,
                        document_type, department, len(encrypted),
                        file.content_type or 'application/octet-stream',
                        description, approval_required, file_hash
                    )
                    
                    # Create approval workflow if required
                    if approval_required:
                        create_approval_workflow(doc_id, get_department_approvers(department))
                    
                    success_count += 1
                    
                except Exception as e:
                    flash(f"Upload failed for {file.filename}: {str(e)}")
        
        if success_count > 0:
            flash(f"{success_count} document(s) uploaded successfully!")
    
    else:
        # Regular user file upload with enhanced security
        uploaded_files = request.files.getlist("file")
        user_folder = os.path.join(BASE_UPLOAD, session["user"])
        os.makedirs(user_folder, exist_ok=True)
        
        success_count = 0
        
        for file in uploaded_files:
            if file and file.filename:
                try:
                    # Enhanced file validation
                    file_content = file.read()
                    file.seek(0)
                    
                    is_valid, validation_message = enhanced_security.validate_file(file, file_content)
                    if not is_valid:
                        flash(f"File {file.filename}: {validation_message}")
                        continue
                    
                    # Malware scanning
                    is_clean, scan_message = enhanced_security.scan_for_malware(file_content)
                    if not is_clean:
                        flash(f"File {file.filename}: {scan_message}")
                        continue
                    
                    file_id = str(uuid.uuid4())
                    encrypted_filename = f"{file_id}.enc"
                    
                    encrypted = encrypt_file(file_content)
                    file_path = os.path.join(user_folder, encrypted_filename)
                    
                    file_chunk_manager.upload_chunked_file(file_path, encrypted)
                    
                    # Calculate file hash
                    file_hash = enhanced_security.calculate_file_hash(file_content)
                    
                    # Store as simple document for users
                    store_document_metadata(
                        session["user"], encrypted_filename, file.filename,
                        "file", "personal", len(encrypted),
                        file.content_type or 'application/octet-stream',
                        "", False, file_hash
                    )
                    
                    success_count += 1
                    
                except Exception as e:
                    flash(f"Upload failed for {file.filename}: {str(e)}")
        
        if success_count > 0:
            flash(f"{success_count} file(s) uploaded successfully!")
    
    return redirect("/dashboard")

@app.route("/document/<int:doc_id>")
@require_auth()
def view_document(doc_id):
    if not check_document_permission(session["user"], doc_id, 'read'):
        flash("Access denied")
        return redirect("/dashboard")
    
    document = get_document_details(doc_id)
    versions = get_document_versions(doc_id)
    
    # Log access
    log_document_access(doc_id, session["user"], "VIEW")
    
    return render_template("document_view.html", 
                         document=document, 
                         versions=versions)

@app.route("/approve/<int:doc_id>", methods=["POST"])
@require_auth()
def approve_document(doc_id):
    action = request.form.get("action")  # approve/reject
    comments = request.form.get("comments", "")
    
    if action not in ['approve', 'reject']:
        return jsonify({"error": "Invalid action"}), 400
    
    # Check if user can approve this document
    if not can_approve_document(session["user"], doc_id):
        return jsonify({"error": "Not authorized to approve"}), 403
    
    # Update approval workflow
    update_approval_workflow(doc_id, session["user"], action, comments)
    
    # Update document status
    new_status = 'approved' if action == 'approve' else 'rejected'
    update_document_status(doc_id, new_status, session["user"])
    
    log_document_access(doc_id, session["user"], f"APPROVAL_{action.upper()}")
    
    return jsonify({"message": f"Document {action}d successfully"})

@app.route("/new_version/<int:doc_id>", methods=["POST"])
@require_auth()
def upload_new_version(doc_id):
    if not check_document_permission(session["user"], doc_id, 'write'):
        return jsonify({"error": "Access denied"}), 403
    
    file = request.files.get("file")
    changes_description = request.form.get("changes_description", "")
    
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400
    
    try:
        # Get current version
        current_version = get_document_current_version(doc_id)
        new_version = current_version + 1
        
        # Upload new version
        file_id = str(uuid.uuid4())
        encrypted_filename = f"{file_id}.enc"
        
        user_folder = os.path.join(BASE_UPLOAD, session["user"])
        encrypted = encrypt_file(file.read())
        file_path = os.path.join(user_folder, encrypted_filename)
        
        with open(file_path, "wb") as f:
            f.write(encrypted)
        
        # Store version metadata
        store_document_version(doc_id, new_version, encrypted_filename, 
                             session["user"], changes_description)
        
        # Update main document
        update_document_version(doc_id, new_version, encrypted_filename)
        
        log_document_access(doc_id, session["user"], "VERSION_UPLOAD")
        
        return jsonify({"message": "New version uploaded successfully"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/search")
@require_auth()
def search_documents():
    query = request.args.get("q", "")
    doc_type = request.args.get("type", "")
    department = request.args.get("dept", "")
    
    results = search_user_documents(session["user"], query, doc_type, department)
    
    return render_template("search_results.html", 
                         results=results, 
                         query=query,
                         document_types=DOCUMENT_TYPES,
                         departments=DEPARTMENTS)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if register_user(username, password):
            flash("Registration successful! Please login.")
            return redirect("/")
        else:
            flash("Registration failed. Username may already exist.")
    
    return render_template("register.html")

@app.route("/forgot_password")
def forgot_password():
    return render_template("forgot_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/settings")
@require_auth()
def settings():
    user_info = get_user_info(session["user"])
    return render_template("settings.html", user=user_info)

@app.route("/generate_api_key", methods=["POST"])
@require_auth()
def generate_api_key():
    api_key = secrets.token_urlsafe(32)
    
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET api_key=? WHERE username=?", (api_key, session["user"]))
    conn.commit()
    conn.close()
    
    flash("API key generated successfully!")
    return redirect("/settings")

@app.route("/update_profile", methods=["POST"])
@require_auth()
def update_profile():
    organization = request.form.get("organization", "")
    department = request.form.get("department", "")
    
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET organization=?, department=? WHERE username=?", 
              (organization, department, session["user"]))
    conn.commit()
    conn.close()
    
    flash("Profile updated successfully!")
    return redirect("/settings")

@app.route("/change_password", methods=["POST"])
@require_auth()
@csrf_protect
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    if not verify_user(session["user"], current_password):
        flash("Current password is incorrect")
        return redirect("/settings")
    
    if new_password != confirm_password:
        flash("New passwords do not match")
        return redirect("/settings")
    
    if len(new_password) < 6:
        flash("Password must be at least 6 characters long")
        return redirect("/settings")
    
    # Update password
    hashed_password = generate_password_hash(new_password)
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, session["user"]))
    conn.commit()
    conn.close()
    
    flash("Password changed successfully!")
    return redirect("/settings")

# Enterprise Features Routes
@app.route("/admin/backup", methods=["GET", "POST"])
@require_auth(role="admin")
def admin_backup():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "create_backup":
            task_id = async_task_manager.submit_task(backup_manager.create_full_backup)
            flash(f"Backup started. Task ID: {task_id}")
        
        elif action == "cleanup_old":
            backup_manager.cleanup_old_backups()
            flash("Old backups cleaned up successfully")
    
    # Get backup list
    backup_files = list(backup_manager.backup_dir.glob("*.zip"))
    backup_info = []
    
    for backup_file in backup_files:
        stat = backup_file.stat()
        backup_info.append({
            'name': backup_file.name,
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    
    return render_template("admin_backup.html", backups=backup_info)

@app.route("/admin/compliance")
@require_auth(role="admin")
def admin_compliance():
    # Get compliance statistics
    stats = db_manager.get_database_stats()
    retention_report = compliance_manager.generate_retention_report()
    
    return render_template("admin_compliance.html", 
                         stats=stats, 
                         retention_report=retention_report)

@app.route("/admin/audit_report", methods=["POST"])
@require_auth(role="admin")
def generate_audit_report():
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")
    username = request.form.get("username", None)
    
    if username == "":
        username = None
    
    report = compliance_manager.generate_audit_report(start_date, end_date, username)
    
    return jsonify({
        "report_id": report["report_id"],
        "total_events": report["total_events"],
        "download_url": f"/download_report/{report['report_id']}"
    })

@app.route("/admin/system_monitor")
@require_auth(role="admin")
def system_monitor():
    # Get system performance metrics
    system_stats = performance_monitor.get_system_stats()
    
    # Get database performance metrics
    db_stats = db_manager.get_database_stats()
    
    # Get recent performance metrics
    metrics = {
        'upload_avg': performance_monitor.get_average('file_upload_success'),
        'download_avg': performance_monitor.get_average('file_download_success'),
        'search_avg': performance_monitor.get_average('search_documents_success')
    }
    
    return render_template("system_monitor.html", 
                         system_stats=system_stats,
                         db_stats=db_stats,
                         metrics=metrics)

@app.route("/gdpr_export")
@require_auth()
def gdpr_export():
    export_file = compliance_manager.generate_gdpr_report(session["user"])
    
    return send_file(export_file, 
                    as_attachment=True, 
                    download_name=f"gdpr_export_{session['user']}.json")

@app.route("/upload_progress/<task_id>")
@require_auth()
def upload_progress(task_id):
    task_status = async_task_manager.get_task_status(task_id)
    return jsonify(task_status)

@app.route("/download/<int:file_id>")
@require_auth()
def download_file(file_id):
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
        update_file_access(session["user"], file_id)
        
        return Response(
            decrypted_data,
            mimetype=file_info['mime_type'],
            headers={"Content-Disposition": f"attachment; filename={file_info['original_name']}"}
        )
    except Exception as e:
        return f"Download failed: {str(e)}", 500

@app.route("/preview/<int:file_id>")
@require_auth()
def preview_file(file_id):
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
        update_file_access(session["user"], file_id)
        
        return Response(decrypted_data, mimetype=file_info['mime_type'])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete/<int:file_id>", methods=["DELETE"])
@require_auth()
def delete_file(file_id):
    file_info = get_file_metadata(session["user"], file_id)
    if not file_info:
        return jsonify({"error": "File not found"}), 404
    
    user_folder = os.path.join(BASE_UPLOAD, session["user"])
    file_path = os.path.join(user_folder, file_info['filename'])
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remove from database
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        c.execute("DELETE FROM documents WHERE id=? AND username=?", (file_id, session["user"]))
        conn.commit()
        conn.close()
        
        return jsonify({"message": "File deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin")
@require_auth(role="admin")
def admin_dashboard():
    user_documents = get_user_documents(session["user"])
    pending_approvals = get_pending_approvals(session["user"])
    department_docs = get_department_documents(session["user"])
    
    return render_template("dms_dashboard.html", 
                         documents=user_documents,
                         pending_approvals=pending_approvals,
                         department_docs=department_docs,
                         document_types=DOCUMENT_TYPES,
                         departments=DEPARTMENTS)

# Helper functions
def store_document_metadata(username, filename, original_name, doc_type, department, 
                          file_size, mime_type, description, approval_required, file_hash=None):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""INSERT INTO documents 
                 (username, filename, original_name, document_type, department,
                  file_size, mime_type, upload_date, last_modified, description, 
                  approval_required, file_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (username, filename, original_name, doc_type, department,
               file_size, mime_type, datetime.now().isoformat(), 
               datetime.now().isoformat(), description, approval_required, file_hash))
    
    doc_id = c.lastrowid
    conn.commit()
    conn.close()
    return doc_id

@cache_result(ttl=300)  # Cache for 5 minutes
def get_user_documents(username):
    return db_manager.get_user_documents_optimized(username)

def get_pending_approvals(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT d.id, d.original_name, d.document_type, d.upload_date, d.username
                 FROM documents d, approval_workflows aw
                 WHERE d.id = aw.document_id AND aw.approver=? AND aw.status='pending'""",
              (username,))
    
    approvals = []
    for row in c.fetchall():
        approvals.append({
            'id': row[0], 'name': row[1], 'type': row[2], 
            'upload_date': row[3], 'uploaded_by': row[4]
        })
    
    conn.close()
    return approvals

def get_department_documents(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    # Get user's department
    c.execute("SELECT department FROM users WHERE username=?", (username,))
    user_dept = c.fetchone()
    
    if not user_dept or not user_dept[0]:
        return []
    
    c.execute("""SELECT id, original_name, document_type, upload_date, username, status
                 FROM documents WHERE department=? AND username!=? AND status='approved'
                 ORDER BY upload_date DESC LIMIT 10""",
              (user_dept[0], username))
    
    documents = []
    for row in c.fetchall():
        documents.append({
            'id': row[0], 'name': row[1], 'type': row[2],
            'upload_date': row[3], 'uploaded_by': row[4], 'status': row[5]
        })
    
    conn.close()
    return documents

def create_approval_workflow(doc_id, approvers):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    for approver in approvers:
        c.execute("""INSERT INTO approval_workflows 
                     (document_id, approver, created_date)
                     VALUES (?, ?, ?)""",
                  (doc_id, approver, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

def get_department_approvers(department):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT username FROM users 
                 WHERE department=? AND permissions LIKE '%approve%'""", (department,))
    
    approvers = [row[0] for row in c.fetchall()]
    conn.close()
    return approvers

def log_document_access(doc_id, username, action):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""INSERT INTO document_access 
                 (document_id, username, action, timestamp, ip_address)
                 VALUES (?, ?, ?, ?, ?)""",
              (doc_id, username, action, datetime.now().isoformat(),
               request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)))
    
    conn.commit()
    conn.close()

def search_user_documents(username, query, doc_type, department):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    sql = """SELECT id, original_name, document_type, department, upload_date, status
             FROM documents WHERE (username=? OR department IN (
                 SELECT department FROM users WHERE username=?
             )) AND status='approved'"""
    params = [username, username]
    
    if query:
        sql += " AND (original_name LIKE ? OR description LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])
    
    if doc_type:
        sql += " AND document_type=?"
        params.append(doc_type)
    
    if department:
        sql += " AND department=?"
        params.append(department)
    
    sql += " ORDER BY upload_date DESC"
    
    c.execute(sql, params)
    
    results = []
    for row in c.fetchall():
        results.append({
            'id': row[0], 'name': row[1], 'type': row[2],
            'department': row[3], 'upload_date': row[4], 'status': row[5]
        })
    
    conn.close()
    return results

# Missing helper functions for user interface
def get_user_files_with_metadata(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT id, filename, original_name, file_size, mime_type, 
                        upload_date, tags, description
                 FROM documents WHERE username=? ORDER BY upload_date DESC""",
              (username,))
    
    files = []
    for row in c.fetchall():
        files.append({
            'id': row[0], 'filename': row[1], 'original_name': row[2],
            'file_size': row[3], 'mime_type': row[4], 'upload_date': row[5],
            'download_count': 0, 'tags': row[6], 'description': row[7]
        })
    
    conn.close()
    return files

def get_user_statistics(username):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("SELECT plan, storage_used FROM users WHERE username=?", (username,))
    user_data = c.fetchone()
    
    c.execute("SELECT COUNT(*) FROM documents WHERE username=?", (username,))
    file_count = c.fetchone()[0]
    
    conn.close()
    
    plan, storage_used = user_data if user_data else ('free', 0)
    
    return {
        'plan': plan, 'storage_used': storage_used, 'storage_quota': 1000000000,
        'storage_percentage': (storage_used / 1000000000) * 100,
        'file_count': file_count, 'recent_activity': 0
    }

def get_file_metadata(username, file_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT filename, original_name, file_size, mime_type
                 FROM documents WHERE username=? AND id=?""",
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
    
    c.execute("""UPDATE documents 
                 SET last_modified=?
                 WHERE username=? AND id=?""",
              (datetime.now().isoformat(), username, file_id))
    
    conn.commit()
    conn.close()

def get_document_details(doc_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT id, original_name, document_type, department, file_size,
                        upload_date, version, status, description, mime_type
                 FROM documents WHERE id=?""", (doc_id,))
    
    result = c.fetchone()
    conn.close()
    
    if result:
        return {
            'id': result[0], 'original_name': result[1], 'document_type': result[2],
            'department': result[3], 'file_size': result[4], 'upload_date': result[5],
            'version': result[6], 'status': result[7], 'description': result[8],
            'mime_type': result[9]
        }
    return None

def get_document_versions(doc_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT id, version, uploaded_by, upload_date, changes_description
                 FROM document_versions WHERE document_id=? ORDER BY version DESC""",
              (doc_id,))
    
    versions = []
    for row in c.fetchall():
        versions.append({
            'id': row[0], 'version': row[1], 'uploaded_by': row[2],
            'upload_date': row[3], 'changes_description': row[4]
        })
    
    conn.close()
    return versions

def can_approve_document(username, doc_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""SELECT COUNT(*) FROM approval_workflows 
                 WHERE document_id=? AND approver=? AND status='pending'""",
              (doc_id, username))
    
    result = c.fetchone()[0] > 0
    conn.close()
    return result

def update_approval_workflow(doc_id, approver, action, comments):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""UPDATE approval_workflows 
                 SET status=?, comments=?, decision_date=?
                 WHERE document_id=? AND approver=?""",
              (action, comments, datetime.now().isoformat(), doc_id, approver))
    
    conn.commit()
    conn.close()

def update_document_status(doc_id, status, approved_by):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""UPDATE documents 
                 SET status=?, approved_by=?, approval_date=?
                 WHERE id=?""",
              (status, approved_by, datetime.now().isoformat(), doc_id))
    
    conn.commit()
    conn.close()

def get_document_current_version(doc_id):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("SELECT version FROM documents WHERE id=?", (doc_id,))
    result = c.fetchone()
    conn.close()
    
    return result[0] if result else 1

def store_document_version(doc_id, version, filename, username, changes_description):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""INSERT INTO document_versions 
                 (document_id, version, filename, uploaded_by, upload_date, changes_description)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              (doc_id, version, filename, username, datetime.now().isoformat(), changes_description))
    
    conn.commit()
    conn.close()

def update_document_version(doc_id, version, filename):
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    
    c.execute("""UPDATE documents 
                 SET version=?, filename=?, last_modified=?
                 WHERE id=?""",
              (version, filename, datetime.now().isoformat(), doc_id))
    
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
            'plan': result[1] or 'free',
            'storage_used': result[2] or 0,
            'api_key': result[3],
            'organization': result[4],
            'department': result[5]
        }
    return {'username': username, 'plan': 'free', 'storage_used': 0, 'api_key': None, 'organization': None, 'department': None}

if __name__ == "__main__":
    app.run(debug=True)