import sqlite3

try:
    conn = sqlite3.connect('secure_chat.db')
    cursor = conn.cursor()
    cursor.execute("ALTER TABLE messages ADD COLUMN is_spam BOOLEAN DEFAULT 0")
    conn.commit()
    print("Column 'is_spam' added successfully.")
except sqlite3.OperationalError as e:
    print(f"Error: {e}")
finally:
    if conn:
        conn.close()
