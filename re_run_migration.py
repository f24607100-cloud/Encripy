
import sqlite3

try:
    conn = sqlite3.connect('secure_chat.db')
    cursor = conn.cursor()
    # Check if column already exists to avoid error
    cursor.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cursor.fetchall()]
    if "email" not in columns:
        print("Adding 'email' column...")
        cursor.execute("ALTER TABLE users ADD COLUMN email VARCHAR(120)")
        # We need to make it unique, but sqlite ALTER TABLE has limitations.
        # We can add a unique index instead.
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.commit()
        print("Column 'email' added successfully.")
    else:
        print("Column 'email' already exists.")
except sqlite3.OperationalError as e:
    print(f"Error: {e}")
finally:
    if conn:
        conn.close()
