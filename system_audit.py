import sqlite3
conn = sqlite3.connect('database/users.db')
c = conn.cursor()

print("--- USERS ---")
c.execute("SELECT username, role, department FROM users")
for row in c.fetchall():
    print(row)

print("\n--- ALL DOCUMENTS ---")
c.execute("SELECT id, username, original_name, status, upload_date FROM documents")
for row in c.fetchall():
    print(row)

conn.close()
