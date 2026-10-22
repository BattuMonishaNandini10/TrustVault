
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("trustvault.db")

demo_users = [
    ("admin_demo", "AdminDemo123!", "admin"),
    ("owner_demo", "OwnerDemo123!", "owner"),
    ("viewer_demo", "ViewerDemo123!", "viewer"),
]

for username, password, role in demo_users:
    conn.execute(
        """
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        """,
        (username, generate_password_hash(password), role),
    )

conn.commit()
conn.close()

print("Demo accounts created or already exist.")
