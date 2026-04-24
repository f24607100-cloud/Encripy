import sqlite3

def check_last_message():
    try:
        conn = sqlite3.connect('secure_chat.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, encrypted_message, is_spam, timestamp FROM messages ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        
        if row:
            print(f"Last Message ID: {row['id']}")
            # Content is encrypted, so we can't easily read it, but we assume it was the spam message
            print(f"is_spam: {row['is_spam']}")
            print(f"Timestamp: {row['timestamp']}")
        else:
            print("No messages found.")
            
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_last_message()
