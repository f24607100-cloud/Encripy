"""
Migration script to remove is_banned column from users table.
This column is no longer needed in the application.
"""

import sqlite3
import os

# Get the database path
db_path = os.path.join(os.path.dirname(__file__), 'secure_chat.db')

print(f"Connecting to database: {db_path}")

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Check if the column exists
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]
    
    if 'is_banned' in column_names:
        print("Found 'is_banned' column. Removing it...")
        
        # SQLite doesn't support DROP COLUMN directly in older versions
        # We need to recreate the table without the column
        
        # 1. Create a new table without is_banned
        cursor.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE,
                password_hash BLOB(128) NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                totp_secret VARCHAR(32),
                profile_picture VARCHAR(120),
                bio VARCHAR(500),
                created_at DATETIME
            )
        """)
        
        # 2. Copy data from old table to new table
        cursor.execute("""
            INSERT INTO users_new 
            SELECT id, username, email, password_hash, public_key, private_key, 
                   totp_secret, profile_picture, bio, created_at
            FROM users
        """)
        
        # 3. Drop the old table
        cursor.execute("DROP TABLE users")
        
        # 4. Rename the new table
        cursor.execute("ALTER TABLE users_new RENAME TO users")
        
        # Commit the changes
        conn.commit()
        print("Successfully removed 'is_banned' column from users table.")
    else:
        print("Column 'is_banned' does not exist. No action needed.")
        
except Exception as e:
    print(f"Error during migration: {e}")
    conn.rollback()
    raise
finally:
    conn.close()

print("Migration completed successfully!")
