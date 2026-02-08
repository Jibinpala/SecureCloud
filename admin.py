import sqlite3
import os

def get_all_users():
    conn = sqlite3.connect("database/users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    conn.close()
    return users

def get_all_files():
    files = []
    base_path = "encrypted_files/users"
    
    if os.path.exists(base_path):
        for username in os.listdir(base_path):
            user_path = os.path.join(base_path, username)
            if os.path.isdir(user_path):
                for filename in os.listdir(user_path):
                    file_path = os.path.join(user_path, filename)
                    if os.path.isfile(file_path):
                        files.append({
                            'username': username,
                            'filename': filename,
                            'size': os.path.getsize(file_path)
                        })
    
    return files