import sqlite3
import os

path = os.path.join(os.path.dirname(__file__), "cyberscan.db")
print("DB path:", path)
print("Exists:", os.path.exists(path))
conn = sqlite3.connect(path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
rows = cur.execute(
    "SELECT id, username, email, is_active, is_admin, is_super_admin, org_id, password_hash FROM users WHERE email LIKE '%gmail.com%';"
).fetchall()
for row in rows:
    print(dict(row))
conn.close()
