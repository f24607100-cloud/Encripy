import sqlite3
import glob
import os

# Find the database
db_files = glob.glob("*.db")
print(f"Database files found: {db_files}")

for db_file in db_files:
    print(f"\n--- Checking {db_file} ---")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    print("Users table columns:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    conn.close()
