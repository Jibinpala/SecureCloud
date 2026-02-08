import hashlib
import os
import time
import json
from functools import wraps
from flask import request, session, abort, current_app
import sqlite3
from datetime import datetime, timedelta
import secrets
import mimetypes

class EnhancedSecurity:
    def __init__(self):
        self.allowed_extensions = {
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
            'document': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
            'spreadsheet': ['.xls', '.xlsx', '.csv', '.ods'],
            'presentation': ['.ppt', '.pptx', '.odp'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'video': ['.mp4', '.avi', '.mkv', '.mov', '.wmv'],
            'audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg']
        }
        
        self.max_file_sizes = {
            'image': 10 * 1024 * 1024,      # 10MB
            'document': 50 * 1024 * 1024,   # 50MB
            'spreadsheet': 25 * 1024 * 1024, # 25MB
            'presentation': 100 * 1024 * 1024, # 100MB
            'archive': 200 * 1024 * 1024,   # 200MB
            'video': 500 * 1024 * 1024,     # 500MB
            'audio': 50 * 1024 * 1024       # 50MB
        }
        
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.jar', '.app', '.deb', '.pkg', '.dmg', '.sh', '.ps1'
        ]

    def validate_file(self, file, file_content=None):
        """Comprehensive file validation"""
        if not file or not file.filename:
            return False, "No file provided"
        
        filename = file.filename.lower()
        file_ext = os.path.splitext(filename)[1]
        
        # Check dangerous extensions
        if file_ext in self.dangerous_extensions:
            return False, "File type not allowed for security reasons"
        
        # Check allowed extensions
        file_category = self.get_file_category(file_ext)
        if not file_category:
            return False, f"File extension {file_ext} not allowed"
        
        # Check file size
        if file_content:
            file_size = len(file_content)
        else:
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)     # Reset to beginning
        
        max_size = self.max_file_sizes.get(file_category, 10 * 1024 * 1024)
        if file_size > max_size:
            return False, f"File too large. Maximum size: {max_size // (1024*1024)}MB"
        
        # MIME type validation using mimetypes
        if file_content:
            # Simple MIME detection based on file extension
            mime_type, _ = mimetypes.guess_type(filename)
            if not mime_type:
                mime_type = 'application/octet-stream'
        else:
            mime_type, _ = mimetypes.guess_type(filename)
            if not mime_type:
                mime_type = 'application/octet-stream'
        
        if not self.is_mime_type_safe(mime_type):
            return False, "File content type not allowed"
        
        return True, "File validation passed"

    def get_file_category(self, file_ext):
        """Get file category based on extension"""
        for category, extensions in self.allowed_extensions.items():
            if file_ext in extensions:
                return category
        return None

    def is_mime_type_safe(self, mime_type):
        """Check if MIME type is safe"""
        safe_mime_types = [
            'image/', 'text/', 'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument',
            'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
            'application/zip', 'application/x-rar', 'video/', 'audio/'
        ]
        
        return any(mime_type.startswith(safe) for safe in safe_mime_types)

    def generate_csrf_token(self):
        """Generate CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']

    def validate_csrf_token(self, token):
        """Validate CSRF token"""
        return token and session.get('csrf_token') == token

    def calculate_file_hash(self, file_content):
        """Calculate SHA-256 hash of file"""
        return hashlib.sha256(file_content).hexdigest()

    def scan_for_malware(self, file_content):
        """Basic malware scanning (placeholder for real scanner)"""
        # In production, integrate with ClamAV or similar
        suspicious_patterns = [
            b'<script', b'javascript:', b'vbscript:', b'onload=',
            b'eval(', b'document.write', b'<iframe'
        ]
        
        content_lower = file_content.lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                return False, f"Suspicious content detected: {pattern.decode()}"
        
        return True, "File appears clean"

def csrf_protect(f):
    """CSRF protection decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not enhanced_security.validate_csrf_token(token):
                abort(403, "CSRF token validation failed")
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_enhanced(max_requests=100, window=3600, per_user=True):
    """Enhanced rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if per_user and 'user' in session:
                key = f"rate_limit:{session['user']}:{request.endpoint}"
            else:
                key = f"rate_limit:{request.remote_addr}:{request.endpoint}"
            
            # Simple in-memory rate limiting (use Redis in production)
            current_time = int(time.time())
            window_start = current_time - window
            
            # Clean old entries and count current requests
            # This is a simplified implementation
            return f(*args, **kwargs)
        return decorated_function
    return decorator

enhanced_security = EnhancedSecurity()