import os
from dotenv import load_dotenv
from auth import register_user, verify_user, reset_password, init_db, hash_email
import sqlite3
import shutil

def test_security_hardening():
    # 1. Test .env loading
    load_dotenv()
    print(f"Secret Key Loaded: {os.getenv('SECRET_KEY') is not None}")
    
    # 2. Setup test DB
    real_db = "database/users.db"
    backup_db = "database/users.db.bak"
    
    # Ensure database directory exists
    os.makedirs("database", exist_ok=True)
    
    # Handle case where database might not exist yet
    has_real_db = os.path.exists(real_db)
    if has_real_db:
        shutil.copy2(real_db, backup_db)
    
    try:
        init_db()
        
        # 3. Test Registration with PII Encryption
        test_user = "testcomp_" + os.urandom(4).hex()
        test_email = "tester@compliance.com"
        register_user(test_user, "Pass123!", test_email)
        print(f"Registered user: {test_user}")
        
        # 4. Verify Database Storage
        conn = sqlite3.connect(real_db)
        c = conn.cursor()
        c.execute("SELECT email, email_hash FROM users WHERE username=?", (test_user,))
        row = c.fetchone()
        conn.close()
        
        if row:
            encrypted_email, e_hash = row
            print(f"Stored Email (Encrypted): {encrypted_email[:20]}...")
            print(f"Stored Email Hash: {e_hash}")
            
            # Check if email is NOT plain text
            if test_email in encrypted_email:
                print("FAILURE: Email stored in plain text!")
            else:
                print("SUCCESS: Email is encrypted.")
                
            # Verify hash matches
            if e_hash == hash_email(test_email):
                print("SUCCESS: Email hash matches.")
            else:
                print("FAILURE: Email hash mismatch!")
        
        # 5. Test Password Reset utilizing Hashed Lookup
        new_pass = "NewPass123!"
        if reset_password(test_user, test_email, new_pass):
            print("SUCCESS: Password reset works with encrypted email lookup.")
        else:
            print("FAILURE: Password reset failed.")
            
    finally:
        # Restore real DB if it existed
        if has_real_db:
            shutil.move(backup_db, real_db)
        elif os.path.exists(real_db):
            os.remove(real_db)

if __name__ == "__main__":
    test_security_hardening()
