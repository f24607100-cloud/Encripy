
import sqlite3
import os

db_path = 'instance/secure_chat.db'

if not os.path.exists(db_path):
    print(f"Database not found: {db_path}")
else:
    print(f"Migrating {db_path}...")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if "email" not in columns:
            print("Adding 'email' column...")
            cursor.execute("ALTER TABLE users ADD COLUMN email VARCHAR(120)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.commit()
            print("Column 'email' added successfully.")
        else:
            print("Column 'email' already exists.")
            
    except sqlite3.OperationalError as e:
        print(f"Error migrating {db_path}: {e}")
    finally:
        if conn:
            conn.close()
