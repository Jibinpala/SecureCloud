import sqlite3
import os

db_path = "database/users.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Upgrade 'user' to premium plan
c.execute("UPDATE users SET plan='premium' WHERE username='user'")

# Log the manual upgrade event
from datetime import datetime
timestamp = datetime.now().isoformat()
c.execute("INSERT INTO security_logs (username, action, status, details, timestamp, ip_address) VALUES (?,?,?,?,?,?)",
          ('user', 'PLAN_UPGRADE', 'SUCCESS', 'Manually upgraded to PREMIUM plan (1GB)', timestamp, '127.0.0.1'))

conn.commit()
print("SUCCESS: User 'user' upgraded to PREMIUM plan.")
conn.close()
