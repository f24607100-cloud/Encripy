from __future__ import annotations

from datetime import datetime

from sqlalchemy import func

from database import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True) # Email is optional for now to support existing users
    password_hash = db.Column(db.LargeBinary(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    profile_picture = db.Column(db.String(120), nullable=True)
    bio = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_banned(self):
        return False

    messages_sent = db.relationship(
        "Message",
        back_populates="sender_user",
        foreign_keys="Message.sender_id",
        lazy="dynamic",
    )
    messages_received = db.relationship(
        "Message",
        back_populates="receiver_user",
        foreign_keys="Message.receiver_id",
        lazy="dynamic",
    )

    friendships_sent = db.relationship(
        "Friendship",
        foreign_keys="Friendship.sender_id",
        backref="sender",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    friendships_received = db.relationship(
        "Friendship",
        foreign_keys="Friendship.receiver_id",
        backref="receiver",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.username}>"


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)
    hmac = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_spam = db.Column(db.Boolean, default=False)
    sentiment = db.Column(db.String(20), nullable=True) # positive, neutral, negative

    sender_user = db.relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    receiver_user = db.relationship("User", foreign_keys=[receiver_id], back_populates="messages_received")


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class BruteForceLog(db.Model):
    __tablename__ = "brute_force_logs"

    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(32), nullable=False)
    attempts = db.Column(db.Integer, nullable=False)
    duration_ms = db.Column(db.Float, nullable=False)
    result = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Story(db.Model):
    __tablename__ = "stories"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content_filename = db.Column(db.String(120), nullable=False)
    caption = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    user = db.relationship("User", backref=db.backref("stories", lazy=True))


class Friendship(db.Model):
    __tablename__ = "friendships"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)  # pending, accepted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('sender_id', 'receiver_id', name='unique_friendship'),
    )


class FeedPost(db.Model):
    __tablename__ = "feed_posts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User", backref=db.backref("feed_posts", lazy=True))
    likes = db.relationship("FeedLike", backref="post", lazy="dynamic", cascade="all, delete-orphan")
    comments = db.relationship("FeedComment", backref="post", lazy="dynamic", cascade="all, delete-orphan")


class FeedLike(db.Model):
    __tablename__ = "feed_likes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("feed_posts.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_feed_like'),
    )


class FeedComment(db.Model):
    __tablename__ = "feed_comments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("feed_posts.id"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("feed_comments", lazy=True))

