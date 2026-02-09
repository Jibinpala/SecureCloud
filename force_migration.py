from database_manager import db_manager
import sys

def migrate():
    print("Starting forced migration...")
    
    # Check if we are connected to Postgres
    if not db_manager.is_postgres:
        print("ERROR: Not connected to Postgres. Check your .env file.")
        return

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
            print(f"Adding column {col_name}...")
            db_manager.execute_query(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            print(f"Successfully added {col_name}")
        except Exception as e:
            if "already exists" in str(e).lower():
                print(f"Column {col_name} already exists.")
            else:
                print(f"Error adding {col_name}: {e}")

    # Also check documents table
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
            print(f"Added doc column {col_name}")
        except Exception as e:
            if "already exists" in str(e).lower():
                pass
            else:
                print(f"Error adding doc column {col_name}: {e}")

    print("Migration complete!")

if __name__ == "__main__":
    migrate()
