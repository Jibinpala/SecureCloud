import sqlite3
conn = sqlite3.connect('database/users.db')
c = conn.cursor()
c.execute("SELECT status, COUNT(*) FROM documents WHERE username='user' GROUP BY status")
for row in c.fetchall():
    print(f"STATUS: {row[0]} | COUNT: {row[1]}")
conn.close()
