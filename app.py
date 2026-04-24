from __future__ import annotations

import os
import secrets
import json
import time
import io
import base64
from datetime import datetime, timedelta
from functools import wraps
from sentiment_analysis.sentiment import predict_sentiment

import pyotp
import qrcode
import otp
from Crypto.Cipher import AES as CryptoAES

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
    send_file,
    send_from_directory,
)
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, ValidationError

from config import Config
from crypto import encryption, hashing, key_exchange, utils
from crypto.encryption import EncryptedPayload
from database import db
from database.models import BruteForceLog, LoginAttempt, Message, User, Story, Friendship, FeedPost, FeedLike, FeedComment
from spam.spam import predict_spam
from spam_image.spamimage import predict_spam_image


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app


def current_user() -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


def store_login_attempt(username: str, success: bool, ip: str | None = None) -> None:
    attempt = LoginAttempt(username=username, success=success, ip_address=ip)
    db.session.add(attempt)
    db.session.commit()


def lockout_remaining_seconds(username: str, app: Flask) -> int:
    if not username:
        return 0
    threshold = app.config["LOGIN_LOCKOUT_THRESHOLD"]
    duration = app.config["LOGIN_LOCKOUT_DURATION_SECONDS"]
    window_minutes = app.config["LOGIN_ATTEMPT_WINDOW_MINUTES"]

    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)

    base_query = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.success.is_(False),
        LoginAttempt.created_at >= window_start,
    )

    failure_count = base_query.count()
    if failure_count < threshold:
        return 0

    last_attempt = (
        base_query.order_by(LoginAttempt.created_at.desc()).first()
    ).created_at
    expires_at = last_attempt + timedelta(seconds=duration)
    remaining = (expires_at - now).total_seconds()
    return int(remaining) if remaining > 0 else 0


def _session_key(user_a: int, user_b: int) -> str:
    return f"shared_key:{min(user_a, user_b)}:{max(user_a, user_b)}"


def get_shared_key_for_users(user_a: User, user_b: User) -> bytes:
    key_name = _session_key(user_a.id, user_b.id)
    cached = session.get(key_name)
    if cached:
        return utils.decode_bytes(cached)

    private_key = int(user_a.private_key)
    peer_public = int(user_b.public_key)
    shared_key = key_exchange.compute_shared_key(private_key, peer_public)
    session[key_name] = utils.encode_bytes(shared_key)
    session.modified = True
    return shared_key


class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')])

    def validate_username(self, username):
        if username.data != current_user().username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exists.')



def register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        if current_user():
            return redirect(url_for("chat_list"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username")
            email = request.form.get("email")
            password = request.form.get("password")

            if not username or not email or not password:
                flash("Username, email, and password are required.", "danger")
                return redirect(url_for("register"))

            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return redirect(url_for("register"))
            
            if User.query.filter_by(email=email).first():
                flash("Email already registered.", "danger")
                return redirect(url_for("register"))

            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return redirect(url_for("register"))

            # Check for special characters
            special_characters = set("!@#$%^&*()-_=+[]{}|;:,.<>?/")
            if not any(char in special_characters for char in password):
                flash("Password must contain at least one special character (e.g., ! @ # $).", "danger")
                return redirect(url_for("register"))

            # Generate OTP
            otp_code = otp.generate_code()
            
            # Store registration data in session temporarily
            session['temp_user'] = {
                'username': username,
                'email': email,
                'password': password,
                'otp': otp_code,
                'timestamp': datetime.utcnow().timestamp()
            }
            
            # Send OTP
            email_sent, email_message = otp.send_verification_email(email, otp_code)
            if not email_sent:
                flash(
                    f"OTP email could not be sent. {email_message} "
                    "For Gmail, use your Gmail address for MAIL_USERNAME and a 16-character App Password for MAIL_PASSWORD.",
                    "danger",
                )
                if app.debug:
                    flash(f"Debug OTP (email disabled): {otp_code}", "warning")
                return redirect(url_for("register"))

            flash("A verification code has been sent to your email.", "info")
            return redirect(url_for("verify_registration"))

        return render_template("register.html")

    @app.route("/verify_registration", methods=["GET", "POST"])
    def verify_registration():
        if 'temp_user' not in session:
            return redirect(url_for("register"))
            
        if request.method == "POST":
            entered_otp = request.form.get("otp")
            temp_user = session.get('temp_user')
            
            # Check expiration (10 minutes)
            if datetime.utcnow().timestamp() - temp_user['timestamp'] > 600:
                session.pop('temp_user', None)
                flash("OTP has expired. Please register again.", "danger")
                return redirect(url_for("register"))
                
            if entered_otp == temp_user['otp']:
                # OTP Verified - Create User
                hashed = hashing.hash_password(temp_user['password'])
                
                # Generate DH Keys
                key_pair = key_exchange.generate_key_pair()
                
                new_user = User(
                    username=temp_user['username'],
                    email=temp_user['email'],
                    password_hash=hashed,
                    private_key=str(key_pair.private_key),
                    public_key=str(key_pair.public_key),
                )
                
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    
                    session.pop('temp_user', None)
                    flash("Registration successful! Please login.", "success")
                    return redirect(url_for("login"))
                    
                except IntegrityError:
                    db.session.rollback()
                    flash("Error creating account.", "danger")
                    return redirect(url_for("register"))
            else:
                flash("Invalid OTP. Please try again.", "danger")
        
        return render_template("verify_otp.html")


    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            lockout_seconds = lockout_remaining_seconds(username, app)
            if lockout_seconds > 0:
                flash(
                    f"Too many failed attempts. Please wait {lockout_seconds} seconds before trying again.",
                    "danger",
                )
                return redirect(url_for("login"))

            user = User.query.filter_by(username=username).first()

            # Verify Password
            if user and hashing.verify_password(password, user.password_hash):
                # Success
                session.clear() # Clear existing session to prevent session fixation
                session["user_id"] = user.id
                session["username"] = user.username
                store_login_attempt(username, True, request.remote_addr)
                flash("Login successful.", "success")
                return redirect(url_for("chat_list"))
            else:
                store_login_attempt(username, False, request.remote_addr)
                remaining = lockout_remaining_seconds(username, app)
                if remaining > 0:
                    flash(
                        f"Too many failed attempts. Please wait {remaining} seconds before trying again.",
                        "danger",
                    )
                else:
                    flash("Invalid credentials.", "danger")
                return redirect(url_for("login"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/forgot_password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email")
            user = User.query.filter_by(email=email).first()
            
            if user:
                otp_code = otp.generate_code()
                session['reset_email'] = email
                session['reset_otp'] = otp_code
                session['reset_timestamp'] = datetime.utcnow().timestamp()
                
                email_sent, _ = otp.send_verification_email(email, otp_code)
                if not email_sent:
                    flash(
                        "OTP email could not be sent. Configure MAIL_USERNAME and MAIL_PASSWORD (.env).",
                        "danger",
                    )
                    if app.debug:
                        flash(f"Debug OTP (email disabled): {otp_code}", "warning")
                else:
                    flash("If an account exists with this email, a code has been sent.", "info")
                return redirect(url_for("verify_reset_otp"))
            else:
                # Don't reveal if email exists or not
                flash("If an account exists with this email, a code has been sent.", "info")
                return redirect(url_for("verify_reset_otp"))
                
        return render_template("forgot_password.html")

    @app.route("/verify_reset_otp", methods=["GET", "POST"])
    def verify_reset_otp():
        # Check if we have a pending reset
        if 'reset_email' not in session:
             return redirect(url_for("forgot_password"))

        if request.method == "POST":
            entered_otp = request.form.get("otp")
            
            # Check expiration
            if datetime.utcnow().timestamp() - session.get('reset_timestamp', 0) > 600:
                session.pop('reset_email', None)
                session.pop('reset_otp', None)
                flash("OTP has expired. Please request a new one.", "danger")
                return redirect(url_for("forgot_password"))
            
            if entered_otp == session.get('reset_otp'):
                session['reset_verified'] = True
                return redirect(url_for("reset_password"))
            else:
                flash("Invalid OTP.", "danger")
                
        return render_template("verify_otp.html")

    @app.route("/reset_password", methods=["GET", "POST"])
    def reset_password():
        if not session.get('reset_verified') or not session.get('reset_email'):
            return redirect(url_for("forgot_password"))
            
        if request.method == "POST":
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return redirect(url_for("reset_password"))
            
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return redirect(url_for("reset_password"))
                
            user = User.query.filter_by(email=session['reset_email']).first()
            if user:
                user.password_hash = hashing.hash_password(password)
                db.session.commit()
                
                # Cleanup session
                session.pop('reset_email', None)
                session.pop('reset_otp', None)
                session.pop('reset_verified', None)
                session.pop('reset_timestamp', None)
                
                flash("Password reset successful. Please login.", "success")
                return redirect(url_for("login"))
            else:
                flash("Error resetting password.", "danger")
                
        return render_template("reset_password.html")

    @app.route("/chat")
    @login_required
    def chat_list():
        user = current_user()
        
        # Fetch pending received requests
        pending_requests = db.session.query(Friendship, User).join(User, Friendship.sender_id == User.id).filter(
            Friendship.receiver_id == user.id,
            Friendship.status == "pending"
        ).all()
        
        # Fetch accepted friends
        # We need to check both sender and receiver roles
        friends_sent = db.session.query(User).join(Friendship, Friendship.receiver_id == User.id).filter(
            Friendship.sender_id == user.id,
            Friendship.status == "accepted"
        )
        friends_received = db.session.query(User).join(Friendship, Friendship.sender_id == User.id).filter(
            Friendship.receiver_id == user.id,
            Friendship.status == "accepted"
        )
        friends = friends_sent.union(friends_received).all()
        
        # Fetch active stories for friends only
        friend_ids = [f.id for f in friends] + [user.id] # Include self
        now = datetime.utcnow()
        active_stories = Story.query.filter(
            Story.expires_at >= now,
            Story.user_id.in_(friend_ids)
        ).order_by(Story.created_at.desc()).all()
        
        return render_template("chat_list.html", friends=friends, pending_requests=pending_requests, active_stories=active_stories)

    @app.route("/chat/<string:username>")
    @login_required
    def chat(username: str):
        user = current_user()
        
        # Verify partner is a friend
        partner = User.query.filter_by(username=username).first_or_404()
        
        # Check friendship status
        is_friend = Friendship.query.filter(
            ((Friendship.sender_id == user.id) & (Friendship.receiver_id == partner.id) & (Friendship.status == 'accepted')) |
            ((Friendship.sender_id == partner.id) & (Friendship.receiver_id == user.id) & (Friendship.status == 'accepted'))
        ).first()
        
        if not is_friend:
             flash("You can only chat with friends.", "warning")
             return redirect(url_for('chat_list'))

        # Fetch accepted friends for sidebar
        friends_sent = db.session.query(User).join(Friendship, Friendship.receiver_id == User.id).filter(
            Friendship.sender_id == user.id,
            Friendship.status == "accepted"
        )
        friends_received = db.session.query(User).join(Friendship, Friendship.sender_id == User.id).filter(
            Friendship.receiver_id == user.id,
            Friendship.status == "accepted"
        )
        contacts = friends_sent.union(friends_received).all()

        get_shared_key_for_users(user, partner)
        return render_template(
            "chat.html",
            partner=partner,
            contacts=contacts,
            current_user=user,
            poll_interval=app.config["CHAT_POLL_INTERVAL"],
        )

    @app.route("/send_message", methods=["POST"])
    @login_required
    def send_message():
        try:
            user = current_user()
            data = request.get_json()
            receiver_username = data.get("receiver")
            plaintext = data.get("message", "").strip()
            ttl = data.get("ttl")

            if not plaintext:
                return jsonify({"error": "Message cannot be empty."}), 400

            receiver = User.query.filter_by(username=receiver_username).first()
            if not receiver:
                return jsonify({"error": "Receiver not found."}), 404
                
            # Verify friendship
            is_friend = Friendship.query.filter(
                ((Friendship.sender_id == user.id) & (Friendship.receiver_id == receiver.id) & (Friendship.status == 'accepted')) |
                ((Friendship.sender_id == receiver.id) & (Friendship.receiver_id == user.id) & (Friendship.status == 'accepted'))
            ).first()
            
            if not is_friend:
                return jsonify({"error": "You can only message friends."}), 403

            # Calculate expiration if TTL is provided
            expires_at = None
            if ttl and int(ttl) > 0:
                expires_at = datetime.utcnow() + timedelta(seconds=int(ttl))

            # Check for spam (text or image)
            is_spam = False
            try:
                if plaintext.startswith("[IMAGE]:"):
                    # Spam image detection
                    import tempfile
                    import base64
                    
                    # Extract base64 image data
                    base64_data = plaintext[8:]  # Remove "[IMAGE]:" prefix
                    
                    # Decode and save to temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
                        tmp_path = tmp_file.name
                        img_data = base64.b64decode(base64_data.split(',')[1] if ',' in base64_data else base64_data)
                        tmp_file.write(img_data)
                    
                    # Predict spam
                    try:
                        if predict_spam_image(tmp_path) == 1:
                            is_spam = True
                    finally:
                        # Clean up temp file
                        if os.path.exists(tmp_path):
                            os.remove(tmp_path)
                            
                elif plaintext:
                    # Spam text detection
                    if predict_spam(plaintext) == 1:
                        is_spam = True
            except Exception as e:
                print(f"Spam detection error: {e}")

            # Sentiment Analysis
            sentiment_label = "neutral"
            try:
                if plaintext and not plaintext.startswith("[IMAGE]:"):
                   sentiment_result = predict_sentiment(plaintext)
                   sentiment_label = sentiment_result.get("sentiment", "neutral")
            except Exception as e:
                print(f"Sentiment analysis error: {e}")

            # Encrypt the message using shared key
            shared_key = get_shared_key_for_users(user, receiver)
            payload = encryption.encrypt(shared_key, plaintext)

            message = Message(
                sender_id=user.id,
                receiver_id=receiver.id,
                encrypted_message=utils.encode_bytes(payload.ciphertext),
                iv=utils.encode_bytes(payload.iv),
                hmac=utils.encode_bytes(payload.hmac_tag),
                expires_at=expires_at,
                sentiment=sentiment_label
            )
            message.is_spam = is_spam
            db.session.add(message)
            db.session.commit()

            return jsonify({"status": "sent"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


    @app.route("/get_messages/<username>")
    @login_required
    def get_messages(username):
        current_user_obj = current_user() # Get the current user object
        if not current_user_obj:
            return jsonify({"error": "User not logged in"}), 401

        other_user = User.query.filter_by(username=username).first()
        if not other_user:
            return jsonify({"error": "User not found"}), 404

        # 1. Delete expired messages relative to NOW
        now = datetime.utcnow()
        # Filter for messages where expires_at is not None AND expires_at is in the past
        expired_count = Message.query.filter(Message.expires_at != None, Message.expires_at < now).delete(synchronize_session=False)
        if expired_count > 0:
            db.session.commit()

        # 2. Fetch remaining messages
        messages = (
            Message.query.filter(
                or_(
                    and_(Message.sender_id == current_user_obj.id, Message.receiver_id == other_user.id),
                    and_(Message.sender_id == other_user.id, Message.receiver_id == current_user_obj.id),
                )
            )
            .order_by(Message.timestamp.asc())
            .all()
        )

        shared_key = get_shared_key_for_users(current_user_obj, other_user)
        serialized = []

        for message in messages:
            try:
                # Attempt to decrypt
                payload = EncryptedPayload(
                    ciphertext=utils.decode_bytes(message.encrypted_message),
                    iv=utils.decode_bytes(message.iv),
                    hmac_tag=utils.decode_bytes(message.hmac),
                )
                plaintext = encryption.decrypt(shared_key, payload)
            except Exception:
                # Fallback for old messages or if decryption fails
                # Also handles the case where simple strings were stored without full encryption structs during testing
                plaintext = message.encrypted_message 
                if len(plaintext) > 200: # detailed check to avoid showing raw base64 of images as text
                     plaintext = "[Encrypted Content]"

            serialized.append(
                {
                    "id": message.id,
                    "sender": message.sender_user.username,
                    "receiver": message.receiver_user.username,
                    "content": plaintext,
                    "timestamp": message.timestamp.isoformat(),
                    "expires_at": message.expires_at.isoformat() if message.expires_at else None,
                    "is_spam": message.is_spam,
                    "sentiment": message.sentiment
                }
            )

        return jsonify(serialized)

    # Feed Routes
    @app.route("/feed")
    @login_required
    def feed():
        return render_template("feed.html")

    @app.route("/api/feed/posts", methods=["GET"])
    @login_required
    def get_feed_posts():
        posts = FeedPost.query.order_by(FeedPost.created_at.desc()).all()
        current_user_id = current_user().id
        
        serialized = []
        for post in posts:
            is_liked = post.likes.filter_by(user_id=current_user_id).first() is not None
            serialized.append({
                "id": post.id,
                "user": {
                    "username": post.user.username,
                    "profile_picture": post.user.profile_picture if post.user.profile_picture else None
                },
                "content": post.content,
                "created_at": post.created_at.isoformat(),
                "likes_count": post.likes.count(),
                "comments_count": post.comments.count(),
                "is_liked": is_liked,
                "comments": [{
                    "id": c.id,
                    "user": c.user.username,
                    "content": c.content,
                    "created_at": c.created_at.isoformat()
                } for c in post.comments.order_by(FeedComment.created_at.asc())]
            })
        return jsonify(serialized)

    @app.route("/api/feed/posts", methods=["POST"])
    @login_required
    def create_feed_post():
        data = request.get_json()
        content = data.get("content", "").strip()
        
        if not content:
            return jsonify({"error": "Content cannot be empty"}), 400
            
        post = FeedPost(
            user_id=current_user().id,
            content=content
        )
        db.session.add(post)
        db.session.commit()
        
        return jsonify({"status": "success", "post_id": post.id})

    @app.route("/api/feed/posts/<int:post_id>/like", methods=["POST"])
    @login_required
    def like_feed_post(post_id):
        post = FeedPost.query.get_or_404(post_id)
        user_id = current_user().id
        
        like = FeedLike.query.filter_by(user_id=user_id, post_id=post_id).first()
        
        if like:
            db.session.delete(like)
            action = "unliked"
        else:
            like = FeedLike(user_id=user_id, post_id=post_id)
            db.session.add(like)
            action = "liked"
            
        db.session.commit()
        return jsonify({"status": "success", "action": action, "likes_count": post.likes.count()})

    @app.route("/api/feed/posts/<int:post_id>/comment", methods=["POST"])
    @login_required
    def comment_feed_post(post_id):
        post = FeedPost.query.get_or_404(post_id)
        data = request.get_json()
        content = data.get("content", "").strip()
        
        if not content:
            return jsonify({"error": "Comment cannot be empty"}), 400
            
        comment = FeedComment(
            user_id=current_user().id,
            post_id=post_id,
            content=content
        )
        db.session.add(comment)
        db.session.commit()
        
        return jsonify({
            "status": "success", 
            "comment": {
                "id": comment.id,
                "user": current_user().username,
                "content": comment.content,
                "created_at": comment.created_at.isoformat()
            }
        })


    # AI Assistant Routes
    @app.route("/ai_assistant", methods=["GET"])
    @login_required
    def ai_assistant():
        return render_template("ai_assistant.html")

    @app.route("/ai_assistant/chat", methods=["POST"])
    @login_required
    def ai_assistant_chat():
        try:
            from openai import OpenAI
            
            data = request.get_json()
            user_message = data.get("message", "").strip()
            conversation_history = data.get("history", [])
            
            if not user_message:
                return jsonify({"error": "Message cannot be empty"}), 400
            
            # Initialize OpenAI client
            client = OpenAI(api_key=app.config["OPENAI_API_KEY"])
            
            # Build messages for API
            messages = [{"role": "system", "content": "You are a helpful AI assistant integrated into a secure chat application. Be concise, friendly, and helpful."}]
            
            # Add conversation history
            for msg in conversation_history[-10:]:  # Keep last 10 messages for context
                messages.append({"role": msg["role"], "content": msg["content"]})
            
            # Add current user message
            messages.append({"role": "user", "content": user_message})
            
            # Call OpenAI API
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=500,
                temperature=0.7
            )
            
            assistant_message = response.choices[0].message.content
            
            return jsonify({
                "response": assistant_message,
                "status": "success"
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # E-Commerce Store Routes (GentsStyling)
    @app.route("/store/")
    @login_required
    def store_landing():
        """Render the GentsStyling landing page"""
        directory = os.path.join(app.root_path, 'GentsStyling')
        return send_from_directory(directory, 'index.html')

    @app.route("/store/<path:filename>")
    @login_required
    def store_assets(filename):
        """Serve assets for GentsStyling store"""
        directory = os.path.join(app.root_path, 'GentsStyling')
        return send_from_directory(directory, filename)

    
    # Fashion Store
    @app.route("/store/fashion")
    @login_required
    def fashion_store():
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "fashion", "index.html")
        return send_file(file_path)
    
    @app.route("/store/fashion/css/<path:filename>")
    def fashion_css(filename):
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "fashion", "css", filename)
        return send_file(file_path)
    
    @app.route("/store/fashion/js/<path:filename>")
    def fashion_js(filename):
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "fashion", "js", filename)
        return send_file(file_path)
    
    @app.route("/store/fashion/products.json")
    def fashion_products():
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "fashion", "products.json")
        return send_file(file_path)
    
    # Luxurious Store
    @app.route("/store/luxurious")
    @login_required
    def luxurious_store():
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "luxurious", "index.html")
        return send_file(file_path)
    
    @app.route("/store/luxurious/css/<path:filename>")
    def luxurious_css(filename):
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "luxurious", "css", filename)
        return send_file(file_path)
    
    @app.route("/store/luxurious/js/<path:filename>")
    def luxurious_js(filename):
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "luxurious", "js", filename)
        return send_file(file_path)
    
    @app.route("/store/luxurious/products.json")
    def luxurious_products():
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "luxurious", "products.json")
        return send_file(file_path)
    
    # Grooming Store
    @app.route("/store/grooming")
    @login_required
    def grooming_store():
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "grooming", "index.html")
        return send_file(file_path)
    
    @app.route("/store/grooming/css/<path:filename>")
    def grooming_css(filename):
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "grooming", "css", filename)
        return send_file(file_path)
    
    @app.route("/store/grooming/js/<path:filename>")
    def grooming_js(filename):
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "grooming", "js", filename)
        return send_file(file_path)
    
    @app.route("/store/grooming/products.json")
    def grooming_products():
        import os
        file_path = os.path.join(os.path.dirname(__file__), "ecommerce", "grooming", "products.json")
        return send_file(file_path)
    
    # E-Commerce API
    @app.route("/api/ecommerce/checkout", methods=["POST"])
    @login_required
    def ecommerce_checkout():
        """Handle checkout for e-commerce orders"""
        from ecommerce.backend.models import Product, Order
        
        data = request.get_json()
        items = data.get('items', [])
        store = data.get('store', 'unknown')
        
        try:
            for item in items:
                order = Order(
                    user_id=current_user.id,
                    product_id=item['id'],
                    quantity=item['quantity'],
                    total_price=item['price'] * item['quantity'],
                    status='completed'
                )
                db.session.add(order)
            
            db.session.commit()
            return jsonify({"success": True, "message": "Order placed successfully"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 500
            

    @app.route("/admin/logs")
    @login_required
    def admin_logs():
        attempts = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(50).all()
        brute_logs = BruteForceLog.query.order_by(BruteForceLog.created_at.desc()).limit(50).all()
        return render_template("admin_logs.html", attempts=attempts, brute_logs=brute_logs)

    @app.route("/hacker/dashboard")
    @login_required
    def hacker_dashboard():
        """Render the Hacker View dashboard."""
        return render_template("hacker_dashboard.html")

    @app.route("/api/sniffer")
    @login_required
    def api_sniffer():
        """API to return the latest encrypted messages for the sniffer view."""
        # Fetch the last 20 messages from all users
        messages = (
            Message.query.order_by(Message.timestamp.desc())
            .limit(20)
            .all()
        )
        
        packet_data = []
        for msg in messages:
            # Note: msg.encrypted_message is already the base64 string in the DB.
            # We don't need to decode it to bytes just to display it.
            # Ideally we show the raw ciphertext, but for the "hacker view" the base64 string is perfect.
            
            packet_data.append({
                "id": msg.id,
                "timestamp": msg.timestamp.strftime("%H:%M:%S"),
                "source_ip": "192.168.1." + str(100 + msg.sender_id), 
                "dest_ip": "192.168.1." + str(100 + msg.receiver_id),
                "protocol": "TLSv1.3",
                "length": len(msg.encrypted_message),
                "encrypted_payload": msg.encrypted_message[:50] + "...",
                "iv": msg.iv[:20] + "..." if msg.iv else "",
                "hmac": msg.hmac[:20] + "..." if msg.hmac else "",
                "type": "ENCRYPTED_DATA"
            })
            
        return jsonify(packet_data)



    @app.route("/brute_force")
    @login_required
    def brute_force_home():
        """Render the Brute Force Lab dashboard."""
        return render_template("brute_force.html")

    @app.route("/brute_force/password", methods=["POST"])
    @login_required
    def brute_force_password():
        """Simulate a dictionary attack on a bcrypt hash."""
        bcrypt_hash = request.form.get("bcrypt_hash")
        dictionary = request.form.get("dictionary", "")
        
        if not bcrypt_hash or not dictionary:
            flash("Please provide both hash and dictionary.", "warning")
            return redirect(url_for("brute_force_home"))

        words = dictionary.splitlines()
        found = False
        cracked_password = None
        
        try:
            import bcrypt
            for word in words:
                word = word.strip()
                if not word: continue
                # In a real tool, this would try to verify. 
                # For this lab simulation, we will assume success if the input hash is valid format
                # and just return the first word as a "simulated" success to show the UI flow,
                # OR we can actually try to check it if we want real functionality.
                # Let's try to actually check it for realism if it's a valid hash.
                try:
                   if bcrypt.checkpw(word.encode('utf-8'), bcrypt_hash.encode('utf-8')):
                       found = True
                       cracked_password = word
                       break
                except ValueError:
                   # Invalid hash format
                   pass
        except Exception as e:
            flash(f"Error during simulation: {str(e)}", "danger")
            return redirect(url_for("brute_force_home"))

        if found:
            flash(f"SUCCESS! Password cracked: {cracked_password}", "success")
        else:
            flash("FAILURE. Password not found in dictionary (or hash invalid).", "danger")
            
        return redirect(url_for("brute_force_home"))

    @app.route("/brute_force/key", methods=["POST"])
    @login_required
    def brute_force_key():
        """Simulate an AES Key Brute Force attack."""
        # Simple placeholder simulation for now to prevent errors
        flash("AES Simulation initiated. (Simulation Mode)", "info")
        return redirect(url_for("brute_force_home"))


    @app.route("/steganography", methods=["GET", "POST"])
    @login_required
    def steganography():
        decoded_message = None
        if request.method == "POST":
            action = request.form.get("action")
            file = request.files.get("image")
            
            if not file or not file.filename:
                flash("No file selected.", "warning")
                return redirect(url_for("steganography"))

            try:
                from crypto import steganography as stego
                import io

                if action == "encode":
                    message = request.form.get("message", "")
                    if not message:
                        flash("Please enter a message to hide.", "warning")
                        return redirect(url_for("steganography"))
                    
                    # Process image
                    img_io = io.BytesIO(file.read())
                    encoded_image = stego.encode_image(img_io, message)
                    
                    # Save to buffer
                    output = io.BytesIO()
                    encoded_image.save(output, format="PNG")
                    output.seek(0)
                    
                    return send_file(
                        output,
                        mimetype="image/png",
                        as_attachment=True,
                        download_name="secret_image.png"
                    )

                elif action == "decode":
                    img_io = io.BytesIO(file.read())
                    decoded_message = stego.decode_image(img_io)
                    flash("Image successfully scanned.", "success")
            
            except Exception as e:
                flash(f"Error processing image: {str(e)}", "danger")

        return render_template("steganography.html", decoded_message=decoded_message)


    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        form = ProfileForm()
        user = current_user()

        if form.validate_on_submit():
            # Update Username
            if form.username.data != user.username:
                user.username = form.username.data
                session["username"] = user.username # Update session
            
            # Update Bio
            user.bio = form.bio.data

            # Handle Profile Picture
            if form.picture.data:
                file = form.picture.data
                filename = secure_filename(f"user_{user.id}_{file.filename}")
                
                # Ensure upload folder exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Store relative path or filename
                user.profile_picture = filename

            try:
                db.session.commit()
                flash("Profile updated successfully.", "success")
                return redirect(url_for("profile"))
            except IntegrityError:
                db.session.rollback()
                flash("Error updating profile. Username might be taken.", "danger")

        elif request.method == "GET":
            form.username.data = user.username
            form.bio.data = user.bio

        return render_template("profile.html", form=form, user=user)


    @app.route("/stories")
    @login_required
    def stories():
        now = datetime.utcnow()
        Story.query.filter(Story.expires_at < now).delete()
        db.session.commit()

        user = current_user()
        friends_sent = db.session.query(User).join(Friendship, Friendship.receiver_id == User.id).filter(
            Friendship.sender_id == user.id,
            Friendship.status == "accepted"
        )
        friends_received = db.session.query(User).join(Friendship, Friendship.sender_id == User.id).filter(
            Friendship.receiver_id == user.id,
            Friendship.status == "accepted"
        )
        friends = friends_sent.union(friends_received).all()
        friend_ids = [f.id for f in friends] + [user.id]

        active_stories = Story.query.filter(
            Story.expires_at >= now,
            Story.user_id.in_(friend_ids)
        ).order_by(Story.created_at.desc()).all()
        
        return render_template("stories.html", stories=active_stories)

    @app.route("/stories/add", methods=["POST"])
    @login_required
    def add_story():
        if 'story_image' not in request.files:
            flash("No image uploaded", "danger")
            return redirect(url_for('stories'))
            
        file = request.files['story_image']
        caption = request.form.get("caption", "").strip()[:200]
        
        if file.filename == '':
            flash("No image selected", "danger")
            return redirect(url_for('stories'))
            
        if file:
            filename = secure_filename(f"story_{current_user().id}_{int(time.time())}.{file.filename.split('.')[-1]}")
            
            # Ensure upload folder exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            new_story = Story(
                user_id=current_user().id,
                content_filename=filename,
                caption=caption,
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(new_story)
            db.session.commit()
            
            flash("Story added!", "success")
            
        return redirect(url_for('stories'))

    @app.route("/stories/reply", methods=["POST"])
    @login_required
    def reply_story():
        story_id = request.form.get("story_id")
        reply_text = request.form.get("message", "").strip()
        
        if not story_id or not reply_text:
            flash("Invalid reply", "danger")
            return redirect(url_for('stories'))
            
        story = Story.query.get(story_id)
        if not story:
            flash("Story not found", "danger")
            return redirect(url_for('stories'))
            
        if story.user_id == current_user().id:
            flash("You cannot reply to your own story", "warning")
            return redirect(url_for('stories'))
            
        recipient = User.query.get(story.user_id)
        if not recipient:
             flash("User not found", "danger")
             return redirect(url_for('stories'))
             
        formatted_reply = f"[Story Reply]: {reply_text}"
        
        from crypto import encryption as crypto_encryption
        shared_key = get_shared_key_for_users(current_user(), recipient)
        encrypted_payload = crypto_encryption.encrypt_message(formatted_reply, shared_key)
        
        new_msg = Message(
            sender_id=current_user().id,
            receiver_id=recipient.id,
            encrypted_message=encrypted_payload.ciphertext,
            iv=encrypted_payload.iv,
            hmac=encrypted_payload.hmac_tag,
        )
        db.session.add(new_msg)
        db.session.commit()
        
        flash(f"Reply sent to {recipient.username}!", "success")
        return redirect(url_for('stories'))


    # Context processors for template data
    @app.context_processor
    def inject_global_data():
        user = current_user()
        active_stories_count = 0
        if user:
            now = datetime.utcnow()
            active_stories_count = Story.query.filter(Story.expires_at >= now).count()
        return dict(current_user=user, active_stories_count=active_stories_count)


    @app.route("/friends/search", methods=["GET"])
    @login_required
    def search_users():
        query = request.args.get("q", "").strip()
        if not query or len(query) < 3:
            return jsonify([])

        current = current_user()
        
        # Sent requests (any status)
        sent = Friendship.query.filter_by(sender_id=current.id).with_entities(Friendship.receiver_id).all()
        # Received requests (any status)
        received = Friendship.query.filter_by(receiver_id=current.id).with_entities(Friendship.sender_id).all()
        
        exclude_ids = {current.id}
        exclude_ids.update(r.receiver_id for r in sent)
        exclude_ids.update(s.sender_id for s in received)
        
        users = User.query.filter(
            User.username.ilike(f"%{query}%"),
            ~User.id.in_(exclude_ids)
        ).limit(10).all()
        
        return jsonify([{"id": u.id, "username": u.username, "profile_picture": u.profile_picture} for u in users])

    @app.route("/friends/add/<int:user_id>", methods=["POST"])
    @login_required
    def add_friend(user_id):
        target_user = User.query.get_or_404(user_id)
        current = current_user()
        
        existing = Friendship.query.filter(
            ((Friendship.sender_id == current.id) & (Friendship.receiver_id == target_user.id)) |
            ((Friendship.sender_id == target_user.id) & (Friendship.receiver_id == current.id))
        ).first()
        
        if existing:
            return jsonify({"status": "error", "message": "Request exists."}), 400
            
        new_request = Friendship(sender_id=current.id, receiver_id=target_user.id, status="pending")
        db.session.add(new_request)
        db.session.commit()
        
        return jsonify({"status": "success", "message": "Friend request sent!"})

    @app.route("/friends/handle/<int:request_id>/<action>", methods=["POST"])
    @login_required
    def handle_friend_request(request_id, action):
        friendship = Friendship.query.get_or_404(request_id)
        current = current_user()
        
        if friendship.receiver_id != current.id:
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
            
        if action == "accept":
            friendship.status = "accepted"
            db.session.commit()
            return jsonify({"status": "success", "message": "Friend request accepted!"})
        elif action == "reject":
            db.session.delete(friendship)
            db.session.commit()
            return jsonify({"status": "success", "message": "Friend request rejected."})
            
        return jsonify({"status": "error", "message": "Invalid action"}), 400


def _mini_aes_key(key: int) -> bytes:
    key_bytes = key.to_bytes(2, byteorder="big", signed=False)
    return (key_bytes * 16)[:32]


def _mini_aes_encrypt(key: int, plaintext: bytes, iv: bytes) -> bytes:
    cipher_key = _mini_aes_key(key)
    cipher = CryptoAES.new(cipher_key, CryptoAES.MODE_CBC, iv)
    pad_len = 16 - (len(plaintext) % 16)
    if pad_len == 0:
        pad_len = 16
    padded = plaintext + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True)

