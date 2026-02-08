import sqlite3
conn = sqlite3.connect('database/users.db')
c = conn.cursor()
c.execute("SELECT id, username, original_name, status, upload_date FROM documents WHERE username='user' ORDER BY id DESC")
print("ALL DOCUMENTS FOR 'user':")
for row in c.fetchall():
    print(f"ID: {row[0]} | NAME: {row[1]} | STATUS: {row[2]} | DATE: {row[3]}")
conn.close()
