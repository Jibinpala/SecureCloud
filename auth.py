import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from crypto import encrypt_file, decrypt_file
from database_manager import db_manager

def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

def init_db():
    # Base schema initialization happens in DatabaseManager initialization logic 
    # or unified_db in app.py. We'll keep this as a schema validation check.
    pass

def register_user(username, password, email=None):
    encrypted_email = None
    email_hash = None
    if email:
        encrypted_email = encrypt_file(email.encode()).decode()
        email_hash = hash_email(email)
        
    query = "INSERT INTO users (username, password, role, email, email_hash) VALUES (?,?,?,?,?)"
    db_manager.execute_query(
        query,
        (username, generate_password_hash(password), "user", encrypted_email, email_hash)
    )

def verify_user(username, password):
    query = "SELECT password, role, suspended FROM users WHERE username=?"
    row = db_manager.execute_query(query, (username,), fetch_one=True)

    if not row:
        return None
    
    # Handle both dict-like and tuple-like result from db_manager
    if isinstance(row, dict):
        p_hash = row['password']
        role = row['role']
        suspended = row.get('suspended', 0)
    else:
        p_hash = row[0]
        role = row[1]
        suspended = row[2] if len(row) > 2 else 0

    if suspended:
        return None
    
    if check_password_hash(p_hash, password):
        return role
    return None

def reset_password(username, email, new_password):
    e_hash = hash_email(email)
    query = "SELECT id FROM users WHERE username=? AND email_hash=?"
    user = db_manager.execute_query(query, (username, e_hash), fetch_one=True)
    
    if user:
        user_id = user['id'] if isinstance(user, dict) else user[0]
        update_query = "UPDATE users SET password=? WHERE id=?"
        db_manager.execute_query(
            update_query,
            (generate_password_hash(new_password), user_id)
        )
        return True
    return False
