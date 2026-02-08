import sqlite3
import os

db_path = "database/users.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

print("ALL DOCUMENTS FOR 'user' (UNTRUNCATED):")
c.execute("SELECT id, original_name, status, upload_date FROM documents WHERE username='user' ORDER BY id DESC")
for row in c.fetchall():
    print(f"ID: {row[0]} | NAME: {row[1]} | STATUS: {row[2]} | DATE: {row[3]}")

conn.close()
