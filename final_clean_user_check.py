import sqlite3
conn = sqlite3.connect('database/users.db')
c = conn.cursor()
c.execute("SELECT id, original_name, status FROM documents WHERE username='user'")
res = c.fetchall()
print(f"COUNT: {len(res)}")
for r in res:
    print(f"ID: {r[0]} | NAME: {r[1]} | STATUS: {r[2]}")
conn.close()
