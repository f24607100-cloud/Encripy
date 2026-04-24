
import sqlite3
import os

db_paths = ['secure_chat.db', 'instance/secure_chat.db']

for db_path in db_paths:
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        continue
        
    print(f"\nChecking {db_path}...")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        
        email_exists = False
        for col in columns:
            if col[1] == 'email':
                email_exists = True
                print(f"  - Found email column: {col}")
        
        if not email_exists:
            print("  - Email column MISSING!")
            
    except sqlite3.OperationalError as e:
        print(f"Error checking {db_path}: {e}")
    finally:
        if conn:
            conn.close()
