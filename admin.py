from database_manager import db_manager
from storage_manager import storage_manager
import os

def get_all_users():
    query = "SELECT id, username, role, email, plan, storage_used, last_login FROM users"
    return db_manager.execute_query(query, fetch_all=True)

def get_all_files():
    query = "SELECT id, original_name, username, file_size, upload_date, status FROM documents"
    return db_manager.execute_query(query, fetch_all=True)

def get_system_stats():
    # Example stats
    user_count = db_manager.execute_query("SELECT COUNT(*) as count FROM users", fetch_one=True)
    file_count = db_manager.execute_query("SELECT COUNT(*) as count FROM documents", fetch_one=True)
    total_storage = db_manager.execute_query("SELECT SUM(storage_used) as total FROM users", fetch_one=True)
    
    return {
        "users": user_count['count'] if isinstance(user_count, dict) else user_count[0],
        "files": file_count['count'] if isinstance(file_count, dict) else file_count[0],
        "storage": total_storage['total'] if isinstance(total_storage, dict) else (total_storage[0] or 0)
    }