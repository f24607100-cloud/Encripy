import sqlite3
from spam.spam import predict_spam

# 1. Check Model Prediction
text = "Claim you won the prize"
prediction = predict_spam(text)
print(f"Prediction for '{text}': {prediction}")

# 2. Check DB Schema
try:
    conn = sqlite3.connect('secure_chat.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(messages)")
    columns = [row[1] for row in cursor.fetchall()]
    print(f"Columns in messages table: {columns}")
    
    if 'is_spam' in columns:
        print("SUCCESS: is_spam column exists.")
    else:
        print("FAILURE: is_spam column MISSING.")
        
    conn.close()
except Exception as e:
    print(f"DB Error: {e}")
