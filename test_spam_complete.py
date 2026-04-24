"""
Comprehensive Spam Detection Test Script
This script verifies the complete spam detection flow.
"""
import sqlite3
from spam.spam import predict_spam

def test_spam_detection():
    print("=" * 60)
    print("SPAM DETECTION COMPREHENSIVE TEST")
    print("=" * 60)
    
    # Test 1: Model Prediction
    print("\n1. Testing spam.py model prediction...")
    test_messages = [
        "Claim you won the prize",
        "Hello, how are you?",
        "Click here to win money NOW!",
        "See you tomorrow"
    ]
    
    for msg in test_messages:
        prediction = predict_spam(msg)
        status = "SPAM" if prediction == 1 else "NOT SPAM"
        print(f"   '{msg[:30]}...' -> {status} ({prediction})")
    
    # Test 2: Database Schema
    print("\n2. Checking database schema...")
    try:
        conn = sqlite3.connect('secure_chat.db')
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(messages)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        
        if 'is_spam' in columns:
            print(f"   ✓ is_spam column exists (type: {columns['is_spam']})")
        else:
            print("   ✗ is_spam column MISSING!")
            
        conn.close()
    except Exception as e:
        print(f"   ✗ Database error: {e}")
    
    # Test 3: Recent Messages
    print("\n3. Checking last 5 messages in database...")
    try:
        conn = sqlite3.connect('secure_chat.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, sender_id, receiver_id, is_spam, timestamp 
            FROM messages 
            ORDER BY id DESC 
            LIMIT 5
        """)
        
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                spam_flag = "🚨 SPAM" if row['is_spam'] else "✓ Normal"
                print(f"   ID {row['id']}: {spam_flag} (from user {row['sender_id']} to {row['receiver_id']})")
        else:
            print("   No messages found in database")
            
        conn.close()
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Restart your Flask server")
    print("2. Send a spam message: 'Claim you won the prize'")
    print("3. Check if it appears in RED in the chat")
    print("=" * 60)

if __name__ == "__main__":
    test_spam_detection()
