
import sys
import os
sys.path.append(os.getcwd())

from unittest.mock import MagicMock
sys.modules['torchvision'] = MagicMock()
sys.modules['torchvision'].__spec__ = MagicMock()
sys.modules['torchvision.transforms'] = MagicMock()
sys.modules['torchvision.models'] = MagicMock()

from app import create_app, db
from config import TestConfig
from database.models import User, Message, Friendship
from sentiment_analysis.sentiment import predict_sentiment

def test_predict_sentiment():
    print("\nTesting predict_sentiment...")
    res = predict_sentiment("I love this!")
    print(f"I love this! -> {res['sentiment']}")
    assert res['sentiment'] == "positive"
    
    res = predict_sentiment("I hate this.")
    print(f"I hate this. -> {res['sentiment']}")
    assert res['sentiment'] == "negative"

@pytest.fixture
def client():
    app = create_app(TestConfig)
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

def test_sentiment_flow(client):
    # Setup users
    from crypto import hashing, key_exchange
    with client.application.app_context():
        kp1 = key_exchange.generate_key_pair()
        u1 = User(username='alice', email='alice@e.com', password_hash=hashing.hash_password('Pass1!'), private_key=str(kp1.private_key), public_key=str(kp1.public_key))
        
        kp2 = key_exchange.generate_key_pair()
        u2 = User(username='bob', email='bob@e.com', password_hash=hashing.hash_password('Pass1!'), private_key=str(kp2.private_key), public_key=str(kp2.public_key))
        
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        
        # Make them friends
        f1 = Friendship(sender_id=u1.id, receiver_id=u2.id, status='accepted')
        db.session.add(f1)
        db.session.commit()

    # Login Alice
    client.post('/login', data={'username': 'alice', 'password': 'Pass1!'}, follow_redirects=True)
    
    # Send Positive Message
    client.post('/send_message', json={
        'receiver': 'bob',
        'message': 'This is amazing!',
        'ttl': 0
    })
    
    # Send Negative Message
    client.post('/send_message', json={
        'receiver': 'bob',
        'message': 'This is terrible.',
        'ttl': 0
    })
    
    # Verify in DB
    with client.application.app_context():
        u1 = User.query.filter_by(username='alice').first()
        msgs = Message.query.filter_by(sender_id=u1.id).all()
        assert len(msgs) == 2
        print("\nMessages in DB:")
        for m in msgs:
            # We need to decrypt to know which is which, or just check if we have one pos and one neg
            # Since we didn't mock encryption, we rely on the sentiment column directly
            print(f"Encrypted Content (len {len(m.encrypted_message)}), Sentiment: {m.sentiment}")
        
        sentiments = [m.sentiment for m in msgs]
        assert "positive" in sentiments
        assert "negative" in sentiments

if __name__ == "__main__":
    # fast run without pytest if needed
    test_predict_sentiment()
    print("Done.")
