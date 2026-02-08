import sqlite3
import os

db_path = "database/users.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Restore all deleted files for 'user'
c.execute("UPDATE documents SET status='active' WHERE username='user' AND status='deleted'")
restored_count = conn.total_changes

# Log the manual restoration event
import secrets
from datetime import datetime
timestamp = datetime.now().isoformat()
c.execute("INSERT INTO security_logs (username, action, status, details, timestamp, ip_address) VALUES (?,?,?,?,?,?)",
          ('user', 'FILE_RESTORE_BULK', 'SUCCESS', f'Manually restored {restored_count} files via system script', timestamp, '127.0.0.1'))

conn.commit()
print(f"SUCCESS: Restored {restored_count} documents for 'user'.")
conn.close()
