
import sqlite3
import os

db_paths = ['secure_chat.db', 'instance/secure_chat.db']

for db_path in db_paths:
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        continue
        
    print(f"\nMigrating {db_path}...")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(messages)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if "sentiment" not in columns:
            print("Adding 'sentiment' column...")
            cursor.execute("ALTER TABLE messages ADD COLUMN sentiment VARCHAR(20)")
            conn.commit()
            print("Column 'sentiment' added successfully.")
        else:
            print("Column 'sentiment' already exists.")
            
    except sqlite3.OperationalError as e:
        print(f"Error migrating {db_path}: {e}")
    finally:
        if conn:
            conn.close()
