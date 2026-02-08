import sqlite3
conn = sqlite3.connect('database/users.db')
c = conn.cursor()

print("--- USERS ---")
c.execute("SELECT username, role FROM users")
for u, r in c.fetchall():
    print(f"'{u}' | Role: '{r}'")

print("\n--- DOCUMENTS SUMMARY ---")
c.execute("SELECT username, status, COUNT(*) FROM documents GROUP BY username, status")
for u, s, count in c.fetchall():
    print(f"User: '{u}' | Status: '{s}' | Count: {count}")

print("\n--- ACTIVE DOCUMENTS FOR 'admin' ---")
c.execute("SELECT id, original_name FROM documents WHERE username='admin' AND status='active'")
for row in c.fetchall():
    print(row)

conn.close()
