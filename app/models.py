from app import db, login
from cryptography.fernet import Fernet
from config import Config
from datetime import datetime, timedelta, timezone
from enum import Enum
from flask import current_app, url_for
from flask_login import current_user, UserMixin
from hashlib import md5
from io import BytesIO
from markdown import markdown
from PIL import Image
from random import SystemRandom
from string import digits
from time import time
from threading import Thread
from typing import List
from werkzeug.security import generate_password_hash, check_password_hash
import bleach
import boto3
import json
import jwt
import os
import pyotp
import redis
import rq
import secrets
import sqlalchemy as sa
import sqlalchemy.orm as so
import uuid

# to_collection_dict() returns a dictionary with user collection representation
# url_for() gets its endpoint from API caller. Some routes require args, which are passed with kwargs
class PaginatedAPIMixin(object):
    @staticmethod
    def to_collection_dict(query, page, per_page, endpoint, **kwargs):
        resources = db.paginate(query, page=page, per_page=per_page,
                                error_out=False)
        data = {
            'items': [item.to_dict() for item in resources.items],
            '_meta': {
                'page': page,
                'per_page': per_page,
                'total_pages': resources.pages,
                'total_items': resources.total
            },
            '_links': {
                'self': url_for(endpoint, page=page, per_page=per_page,
                                **kwargs),
                'next': url_for(endpoint, page=page + 1, per_page=per_page,
                                **kwargs) if resources.has_next else None,
                'prev': url_for(endpoint, page=page - 1, per_page=per_page,
                                **kwargs) if resources.has_prev else None
            }
        }
        return data


follows = sa.Table(
    'follows',
    db.metadata,
    sa.Column('follower_id', sa.BigInteger, sa.ForeignKey('user.id'), primary_key=True),
    sa.Column('followed_id', sa.BigInteger, sa.ForeignKey('user.id'), primary_key=True),
    sa.Column('timestamp', sa.DateTime, default=lambda: datetime.now(timezone.utc))
)


class AccountPermission(Enum):
    READ = 1
    COMMENT = 2
    MESSAGE = 4
    WRITE = 8
    MODERATE = 16
    ADMIN = 32
    ROOT_ADMIN = 64


class UserViewer(Enum):
    PUBLIC = 1
    USER = 2
    FOLLOWER = 4


class PostViewer(Enum):
    PUBLIC = 1
    USER = 2
    FOLLOWER = 4


class User(PaginatedAPIMixin, UserMixin, db.Model):
    __tablename__ = 'user'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True, default=lambda: SystemRandom().randrange(1000000000, 9999999999, 1))
    username: so.Mapped[str] = so.mapped_column(sa.UnicodeText, unique=True, index=True)
    email: so.Mapped[str] = so.mapped_column(sa.UnicodeText, unique=True)
    contact_email: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    password_hash: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    confirmed: so.Mapped[bool] = so.mapped_column(default=False)
    verified: so.Mapped[bool] = so.mapped_column(default=False)
    disabled: so.Mapped[bool] = so.mapped_column(default=False)
    permission: so.Mapped[int] = so.mapped_column(sa.SmallInteger, default=AccountPermission.WRITE.value)
    viewer: so.Mapped[int] = so.mapped_column(sa.SmallInteger, default=UserViewer.PUBLIC.value)
    mfa_enabled: so.Mapped[bool] = so.mapped_column(default=False)
    otp_secret: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    admin_token: so.Mapped[int] = so.mapped_column(sa.SmallInteger, nullable=True)
    about_me: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    photo: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    song: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')
    location: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    phone: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    label: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    banner_flag: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    token: so.Mapped[str] = so.mapped_column(sa.UnicodeText, unique=True, nullable=True)
    editor: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0)
    birth: so.Mapped[datetime] = so.mapped_column(nullable=True)
    joined: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    token_expiration: so.Mapped[datetime] = so.mapped_column(nullable=True)
    last_seen: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    last_notification_read_time: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    last_feed_read_time: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    last_message_read_time: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))

    following: so.WriteOnlyMapped['User'] = so.relationship(
        secondary=follows, primaryjoin=(follows.c.follower_id == id),
        secondaryjoin=(follows.c.followed_id == id),
        back_populates='followers')
    followers: so.WriteOnlyMapped['User'] = so.relationship(
        secondary=follows, primaryjoin=(follows.c.followed_id == id),
        secondaryjoin=(follows.c.follower_id == id),
        back_populates='following')
    messages_sent: so.WriteOnlyMapped['Message'] = so.relationship(foreign_keys='Message.sender_id', back_populates='sender')
    messages_received: so.WriteOnlyMapped['Message'] = so.relationship(foreign_keys='Message.recipient_id', back_populates='recipient')
    posts: so.WriteOnlyMapped['Post'] = so.relationship(back_populates='author')
    comments: so.WriteOnlyMapped['Comment'] = so.relationship(back_populates='author')
    votes: so.WriteOnlyMapped['Vote'] = so.relationship(back_populates='user')
    flags: so.WriteOnlyMapped['Flag'] = so.relationship(back_populates='user')
    notifications: so.WriteOnlyMapped['Notification'] = so.relationship(back_populates='user')
    tasks: so.WriteOnlyMapped['Task'] = so.relationship(back_populates='user')

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(username) <= 64),
        sa.CheckConstraint(sa.func.char_length(email) <= 320),
        sa.CheckConstraint(sa.func.char_length(contact_email) <= 320),
        sa.CheckConstraint(sa.func.char_length(about_me) <= 500),
        sa.CheckConstraint(sa.func.char_length(photo) <= 200),
        sa.CheckConstraint(sa.func.char_length(song) <= 300),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
        sa.CheckConstraint(sa.func.char_length(phone) <= 64),
        sa.CheckConstraint(sa.func.char_length(location) <= 200),
        sa.CheckConstraint(sa.func.char_length(label) <= 32),
        sa.CheckConstraint(sa.func.char_length(banner_flag) <= 28),
        sa.CheckConstraint(sa.func.char_length(token) <= 32),
    )


    @so.validates("email")
    def validate_email(self, key, email):
        if "@" not in email:
            raise ValueError("failed email validation")
        return email
        
    @so.validates("utc_offset")
    def validate_email(self, key, utc_offset):
        if not  -12 < float(utc_offset) < 12:
            raise ValueError("failed utc_offset validation")
        return utc_offset

    def can_view(self):
        if UserViewer(self.viewer).name == 'PUBLIC':
            return True
        elif UserViewer(self.viewer).name != 'PUBLIC' and not current_user.is_authenticated:
            return False
        elif UserViewer(self.viewer).name == 'USER':
            return True
        elif UserViewer(self.viewer).name == 'FOLLOWER' and current_user.is_following(self.username):
            return True
        elif current_user.id == self.id or current_user.can('MODERATE'):
            return True
        else:
            return False

    def is_moderator(self):
        return self.permission == AccountPermission.MODERATE.value

    def is_admin(self):
        return self.permission == AccountPermission.ADMIN.value

    def is_site_admin(self):
        return self.permission == AccountPermission.ROOT_ADMIN.value

    def can(self, key):
        return self.permission >= AccountPermission[key].value

    def get_account_permission(self):
        return AccountPermission(self.permission).name

    def get_viewer(self):
        return UserViewer(self.viewer).name

    def set_permission(self, key):
        if key == 'MODERATE' and not self.confirmed:
            pass
        elif key == 'ADMIN' and not self.confirmed and not self.verified:
            pass
        elif key == 'ROOT_ADMIN' and not self.verified and not self.mfa_enabled:
            pass
        else:
            self.permission = AccountPermission[key].value

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_admin_token(self):
        if self.mfa_enabled:
            self.admin_token = lambda: SystemRandom().randrange(100000, 999999, 1)

    def set_otp_secret(self):
        self.otp_secret = pyotp.random_base32()

    def get_totp_uri(self):
        return f'otpauth://totp/niitii:{self.username}?secret={self.otp_secret}&issuer=niitii'

    def check_totp(self, token):
        totp = pyotp.parse_uri(self.get_totp_uri())
        return totp.verify(token)

#   generate token valid for one hour
    def generate_confirmation_token(self, expiration=3600):
        return jwt.encode({'confirm': self.id, 'exp': time() + expiration}, current_app.config['SECRET_KEY'], algorithm='HS256')


    def generate_change_email_token(self, email, expiration=3600):
        return jwt.encode({'id': self.id, 'email': email, 'exp': time() + expiration}, current_app.config['SECRET_KEY'], algorithm='HS256')

    def verify_change_email_token(self, token):
        if self.id == jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['id']:
            try:
                email = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['email']
            except:
                return False
            return email
        else:
            return False
        
    def get_reset_password_token(self, expiration=600):
        return jwt.encode({'reset_password': self.id, 'exp': time() + expiration}, current_app.config['SECRET_KEY'], algorithm='HS256')

    def follow(self, user):
        if not self.is_following(user.username):
            self.following.add(user)

    def unfollow(self, user):
        if self.is_following(user.username):
            self.following.remove(user)

    def is_following(self, username):
        query = self.following.select().where(User.username == username)
        return db.session.execute(query).scalar() is not None

    def get_followers(self):
        query = self.followers.select()
        return db.session.execute(query).scalars().all()

    def get_following(self):
        query = self.following.select()
        return db.session.execute(query).scalars().all()

    def followers_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.followers.select().subquery())
        return db.session.execute(query).scalar()

    def following_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.following.select().subquery())
        return db.session.execute(query).scalar()

    def following_posts(self):
        Author = so.aliased(User)
        Follower = so.aliased(User)
        return (
            sa.select(Post)
            .join(Post.author.of_type(Author))
            .join(Author.followers.of_type(Follower), isouter=True)
            .where(sa.or_(
                Follower.id == self.id,
                Author.id == self.id,
            ))
            .group_by(Post)
            .order_by(Post.timestamp.desc())
        )

    def get_feed(self):
        return self.following_posts().where(Post.author != current_user).order_by(Post.timestamp.desc(), Post.votes.desc(), Post.comments.desc())

    def get_posts(self):
        return self.posts.select().order_by(Post.timestamp.desc())

    def last_message_received(self):
        return db.session.execute(self.messages_received.select().where(Message.sender == current_user).order_by(Message.id.desc())).scalar()

    def notification_count(self):
        notice = db.session.execute(self.notifications.select().where(Notification.name == 'notification_count')).scalar()
        if notice and notice.get_payload()['count'] != '0':
            return notice.get_payload()['count']
        else:
            return None

    def message_count(self):
        notice = db.session.execute(self.notifications.select().where(Notification.name == 'message_count')).scalar()
        if notice and notice.get_payload()['count'] != '0':
            return notice.get_payload()['count']
        else:
            return None

    def get_comment_count(self):
        query= sa.select(Comment).where(Comment.user_id == self.id)
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        return count

    def feed_count(self):
        last_read_time = self.last_feed_read_time - timedelta(days=5) or datetime(1900, 1, 1)
        query = self.following_posts().where(Post.author != current_user, Post.timestamp > last_read_time)
        return db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()

    def add_notification(self, name, payload, item_id, item_type, utc_offset):
        db.session.add(Notification(user=self, name=name, payload_json=json.dumps(payload), item_id=item_id, item_type=item_type, utc_offset=utc_offset))

    def put_notification_count(self):
        notice = db.session.execute(self.notifications.select().where(Notification.name == 'notification_count')).scalar()

        if notice:
            last_read_time = self.last_notification_read_time or datetime(1900, 1, 1)
            query = self.notifications.select().where((Notification.item_type != "count") & (Notification.timestamp > last_read_time))
            count = db.session.execute(sa.select(sa.func.count())\
            .select_from(query.subquery())).scalar()
            notice.put_payload({"count": f"{count}"})
            notice.timestamp = datetime.now(timezone.utc)
        else:
            payload = {"count": "1"}
            self.add_notification(name='notification_count', payload=payload, item_id=0, item_type='count', utc_offset=0)

    def put_message_count(self):
        notice = db.session.execute(self.notifications.select().where(Notification.name == 'message_count')).scalar()

        if notice:
            query = self.messages_received.select().where(Message.read_timestamp.is_(None))
            count = db.session.execute(sa.select(sa.func.count())\
            .select_from(query.subquery())).scalar()
            notice.put_payload({"count": f"{count}"})
            notice.timestamp = datetime.now(timezone.utc)
        else:
            payload = {"count": "1"}
            self.add_notification(name='message_count', payload=payload, item_id=0, item_type='count', utc_offset=0)

#    submits tasks to RQ queue and adds tasks to DB. name is function name as defined in app/tasks.py. Function prepends app.tasks to build full qualified function name when submitting to RQ.
#     description is presented to user
    def launch_task(self, name, description, *args, **kwargs):
        rq_job = current_app.task_queue.enqueue(f'app.tasks.{name}', self.id, *args, **kwargs)
        task = Task(id=rq_job.get_id(), name=name, description=description, user=self)
        db.session.add(task)
        return task

#   returns complete list of functions that are pending for user
    def get_tasks_in_progress(self):
        query = self.tasks.select().where(Task.complete == False)
        return db.session.execute(query).scalar()

#   returns a specific task. Method is used to prevent user from starting 2+ tasks
    def get_task_in_progress(self, name):
        query = self.tasks.select().where(Task.name == name, Task.complete == False)
        return db.session.execute(query).scalar()

    def get_song(self):
        if self.song:
            return json.loads(self.song)

#   virtual field for API client
    def posts_count(self):
        query= sa.select(Post).where(Post.user_id == self.id)
        return db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()

#     to_dict() converts user object to Python representation, which is converted to JSON
#     last_seen sets the timezone first. SQLAlchemy uses naive datetime objects that are UTC but no timezone recorded
#      _links use url_for() to generate URLs that point to app/api/users.py
#       email will be included only when users request their own data
    def to_dict(self, include_email=False):
        data = {
            'id': self.id,
            'username': self.username,
#            'last_seen': self.last_seen.replace(tzinfo=timezone.utc).isoformat(),
            'about_me': self.about_me,
            'post_count': self.posts_count(),
            'follower_count': self.followers_count(),
            'following_count': self.following_count(),
            '_links': {
                'self': url_for('api.get_user', id=self.id),
                'followers': url_for('api.get_followers', id=self.id),
                'following': url_for('api.get_following', id=self.id),
                'photo': self.photo(256)
            }
        }
        if include_email:
            data['email'] = self.email
        return data

#    client passes user representation in request. Server needs to parse, convert to User objects
#    loop imports field that client can set. Check if there's a value in data arg. Use Python's setarr() to set new values
#    new_user arg checks if it's a new user registration, password will be included. Call the set_password() method to create hash
    def from_dict(self, data, new_user=False):
        for field in ['username', 'email', 'about_me']:
            if field in data:
                setattr(self, field, data[field])
        if new_user and 'password' in data:
            self.set_password(data['password'])

#    secrets.token_hex() from standard library. 16 bytes needed for 32 characters when rendered in Hex
#    method checks if current token has a min left before expiration and return existing token
    def get_token(self, expiration=3600):
        now = datetime.now(timezone.utc)
        if self.token and self.token_expiration.replace(tzinfo=timezone.utc) > now + timedelta(seconds=60):
            return self.token
        self.token = secrets.token_hex(16)
        self.token_expiration = now + timedelta(seconds=expiration)
        db.session.add(self)
        return self.token

#    invalidate token by setting expiration date to one second before current time
    def revoke_token(self):
        self.token_expiration = datetime.now(timezone.utc) - timedelta(seconds=1)

    def query_notification(self):
        return self.notifications.select().where(Notification.item_type != "count").order_by(Notification.timestamp.desc())

    def query_notification_since(self, since):
        return db.session.execute(self.notifications.select()\
        .where((Notification.item_type == "count")\
         & (Notification.timestamp > datetime.fromtimestamp(since)))).scalars()

    def query_old_notification(self):
        return db.session.execute(self.notifications.select()\
        .where((Notification.timestamp < (datetime.now() - timedelta(days=30)))\
         & ((Notification.item_type != "count") | (Notification.item_type == "chatii")))).scalars()

    def query_comment(self):
        return self.comments.select().where(Comment.user_id == self.id).order_by(Comment.timestamp.desc())

    def del_photo(self):
        if self.photo and f"niitii-spaces" in self.photo:
            Photo.del_object('profile-pics', self.photo.removeprefix(f"{Config.SPACES_URL}/profile-pics/"))
        self.photo = None

    def _del_posts(self):
        posts = db.session.execute(self.posts.select()).scalars()
        for p in posts:
            p.del_post()

    def _del_sent_messages(self):
        messages = db.session.execute(self.messages_sent.select()).scalars()
        for m in messages:
            m.del_message()

    def _del_follows(self):
        db.session.execute(follows.delete().where((follows.c.follower_id == self.id) | (follows.c.followed_id == self.id)))

    def _del_comments(self):
        comments = db.session.execute(self.comments.select()).scalars()
        for c in comments:
            c.del_comment()

    def _del_votes(self):
        db.session.execute(self.votes.delete())

    def _del_flags(self):
        db.session.execute(self.flags.delete())

    def _del_notifications(self):
        db.session.execute(self.notifications.delete())

    def del_self(self):
        self.del_photo()
        self._del_posts()
        self._del_sent_messages()
        self._del_follows()
        self._del_comments()
        self._del_votes()
        self._del_flags()
        self._del_notifications()
        db.session.execute(sa.delete(User).where(User.id == self.id))

    @staticmethod
    def query_user(username, scalar=False):
        if scalar:
            return db.session.execute(sa.select(User).where(User.username == username)).scalar()
        else:
            return db.first_or_404(sa.select(User).where(User.username == username))
            
    @staticmethod
    def query_email(email, scalar=False):
        if scalar:
            return db.session.execute(sa.select(User.email).where(User.email == email)).scalar()
        else:
            return db.first_or_404(sa.select(User.email).where(User.email == email))

    @staticmethod
    def confirm_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['confirm']
        except:
            return None
        return db.session.get(User, id)

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return None
        return db.session.get(User, id)

#   check if token is invalid or expired
    @staticmethod
    def check_token(token):
        user = db.session.execute(sa.select(User).where(User.token == token)).scalar()
        if user is None or user.token_expiration.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            return None
        return user


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


tags = sa.Table(
    'tags',
    db.metadata,
    sa.Column('post_id', sa.BigInteger, sa.ForeignKey('post.id'), primary_key=True),
    sa.Column('tag_id', sa.BigInteger, sa.ForeignKey('tag.id'), primary_key=True),
    sa.Column('timestamp', sa.DateTime, default=lambda: datetime.now(timezone.utc))
)


class Post(db.Model):
    __tablename__ = 'post'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    title: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    body: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    body_html: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US', index=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'))
    author: so.Mapped['User'] = so.relationship(back_populates='posts')
    votes: so.Mapped[int] = so.mapped_column(default=0, index=True)
    flags: so.Mapped[int] = so.mapped_column(default=0)
    comments: so.Mapped[int] = so.mapped_column(default=0, index=True)
    pin_comments: so.Mapped[int] = so.mapped_column(default=0)
    removed_comments: so.Mapped[int] = so.mapped_column(default=0)
    direct_comments: so.Mapped[int] = so.mapped_column(default=0)
    disable_comments: so.Mapped[bool] = so.mapped_column(default=False)
    nsfw: so.Mapped[bool] = so.mapped_column(default=False)
    label: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    viewer: so.Mapped[int] = so.mapped_column(sa.SmallInteger, default=PostViewer.PUBLIC.value)
    locked: so.Mapped[bool] = so.mapped_column(default=False)
    photos: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    editor: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0, index=True)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc), index=True)
    edit_timestamp: so.Mapped[datetime] = so.mapped_column(nullable=True)
    tags: so.Mapped[List['Tag']] = so.relationship(secondary=tags, back_populates='posts')    

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(title) <= 3000),
        sa.CheckConstraint(sa.func.char_length(body) <= 20000),
        sa.CheckConstraint('pin_comments <= 2'),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
        sa.CheckConstraint(sa.func.char_length(label) <= 30),
    )

    @so.validates("utc_offset")
    def validate_email(self, key, utc_offset):
        if not  -12 < float(utc_offset) < 12:
            raise ValueError("failed utc_offset validation")
        return utc_offset

    def can_view(self):
        if PostViewer(self.viewer).name == 'PUBLIC':
            return True
        elif PostViewer(self.viewer).name != 'PUBLIC' and not current_user.is_authenticated:
            return False
        elif PostViewer(self.viewer).name == 'USER':
            return True
        elif PostViewer(self.viewer).name == 'FOLLOWER' and current_user.is_following(self.author.username):
            return True
        elif current_user == self.author or current_user.can('MODERATE'):
            return True
        else:
            return False

    def add_photos(p):
        return json.dumps(p)

    def get_photos(self):
        if self.photos:
            return json.loads(self.photos)

    def comments_count(self):
        query= sa.select(Comment).where(Comment.post_id == self.id)
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.comments = count
        return count

    def direct_comments_count(self):
        query= sa.select(Comment).where((Comment.post_id == self.id) & (Comment.direct == True))
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.direct_comments = count
        return count

    def pin_comments_count(self):
        query= sa.select(Comment).where((Comment.post_id == self.id) & (Comment.pinned == True))
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.pin_comments = count
        return count

    def vote_count(self):
        query= sa.select(Vote).where(Vote.post_id == self.id)
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.votes = count
        return count

    def flags_count(self):
        query= sa.select(Flag).where(Flag.post_id == self.id)
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.flags = count
        return count

    def get_comments(self):
        if current_user != self.author:
            return sa.select(Comment).where((Comment.post_id == self.id) & (Comment.direct == False)).order_by(Comment.pinned.desc(), Comment.votes.desc(), Comment.timestamp.desc())
        else:
            return sa.select(Comment).where(Comment.post_id == self.id).order_by(Comment.pinned.desc(), Comment.votes.desc(), Comment.timestamp.desc())

    def get_tags(self):
        post_tags = []
        for tag in self.tags:
            post_tags.append(tag.name)
        return post_tags

    def get_viewer(self):
        return PostViewer(self.viewer).name

    def del_tags(self):
        if self.tags:
            for tag in self.tags:
                tag.del_self()

    def _del_comments(self):
        comments = db.session.execute(sa.select(Comment).where(Comment.post_id == self.id)).scalars()
        for c in comments:
            c.del_comment()

    def _del_flags(self):
        return db.session.execute(sa.delete(Flag).where(Flag.post_id == self.id))

    def _del_votes(self):
        return db.session.execute(sa.delete(Vote).where(Vote.post_id == self.id))

    def _del_photos(self):
        photos = json.loads(self.photos) if self.photos else None
        if photos:
            for p in photos['link']:
                if f"niitii-spaces" in p:
                    Photo.del_object('post-pics', p.removeprefix(f"{Config.SPACES_URL}/post-pics/"))

    def del_self(self):
        self.del_tags()
        self._del_comments()
        self._del_flags()
        self._del_votes()
        self._del_photos()
        db.session.execute(sa.delete(Post).where(Post.id == self.id))

    @staticmethod
    def query_search(q, utc_offset):
        return sa.select(Post).where(Post.title.icontains(q))\
        .order_by(sa.func.abs(Post.utc_offset - utc_offset), Post.timestamp.desc()).limit(100)

    @staticmethod
    def query_post(id, scalar=False):
        if scalar:
            return db.session.execute(sa.select(Post).where(Post.id == id)).scalar()
        else:
            return db.first_or_404(sa.select(Post).where(Post.id == id))

    @staticmethod
    def query_flagged_post():
        return sa.select(Post).where((Post.flags > 0) & (Post.timestamp > (datetime.now(timezone.utc) - timedelta(days=30)))).order_by(Post.flags.desc(), Post.comments.desc(), Post.timestamp.desc()).limit(200)

    @staticmethod
    def get_index(lang):
        if current_user.is_authenticated:
            return sa.select(Post).where((Post.language.in_([current_user.language, lang])) & (Post.utc_offset.between(current_user.utc_offset - 1, current_user.utc_offset + 1)) & (Post.nsfw == False)).order_by(Post.votes.desc(), Post.comments.desc(), Post.timestamp.desc()).limit(200)
        else:
            return sa.select(Post).where((Post.language == lang) & (Post.nsfw == False)).order_by(Post.votes.desc(), Post.comments.desc(), Post.timestamp.desc()).limit(200)

    @staticmethod
    def tag_query(name):
        return db.select(Post)\
        .join(tags, tags.c.post_id == Post.id)\
        .join(Tag, tags.c.tag_id == Tag.id)\
        .where(Tag.name == name)

#     renders HTML version of body and store in body_html in 3 steps
#      1- markdown() converts to HTML
#      2- result is passed to clean() with approved tags. clean() removes unapproved tags
#      3- linkify() converts URLs written in plain text into proper <a> links. Automatic link generation is not officially in Markdown specification
#       https://github.com/yourcelf/bleach-allowlist/blob/main/bleach_allowlist/bleach_allowlist.py - markdown_tags
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = [
            "h1", "h2", "h3", "h4", "h5", "h6",
            "b", "i", "strong", "em", "tt",
            "p", "br",
            "span", "div", "blockquote", "code", "pre", "hr",
            "ul", "ol", "li", "dd", "dt",
            "img",
            "a",
            "sub", "sup",
        ]
        attrs = ['alt', 'href', 'src', 'title']
        protocols= ['http', 'https', 'ftp']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
            tags=allowed_tags, attributes=attrs, protocols=protocols, strip=True))

#Will be auto invoked when body field is set to a new value
db.event.listen(Post.body, 'set', Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = 'comment'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    body_html: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')
    direct: so.Mapped[bool] = so.mapped_column(default=False)
    disabled: so.Mapped[bool] = so.mapped_column(default=False)
    pinned: so.Mapped[bool] = so.mapped_column(default=False)
    ghost: so.Mapped[bool] = so.mapped_column(default=False)
    user_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'))
    author: so.Mapped['User'] = so.relationship(back_populates='comments')
    votes: so.Mapped[int] = so.mapped_column(default=0, index=True)
    post_id: so.Mapped[int] = so.mapped_column(sa.BigInteger)
    parent_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, nullable=True)
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc), index=True)

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(body) <= 5000),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
        sa.CheckConstraint('utc_offset < 12 AND utc_offset > -12'),
    )

    @so.validates("utc_offset")
    def validate_email(self, key, utc_offset):
        if not  -12 < float(utc_offset) < 12:
            raise ValueError("failed utc_offset validation")
        return utc_offset

    def vote_count(self):
        query= sa.select(Vote).where(Vote.comment_id == self.id)
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.votes = count
        return count

    def _del_votes(self):
        return db.session.execute(sa.delete(Vote).where(Vote.comment_id == self.id))

    def del_self(self):
        self._del_votes()
        db.session.execute(sa.delete(Comment).where(Comment.id == self.id))

    @staticmethod
    def query_comment(id, scalar=False):
        if scalar:
            return db.session.execute(sa.select(Comment).where(Comment.id == id)).scalar()
        else:
            return db.first_or_404(sa.select(Comment).where(Comment.id == id))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = [
            "h1", "h2", "h3", "h4", "h5", "h6",
            "b", "i", "strong", "em", "tt",
            "p", "br",
            "span", "div", "blockquote", "code", "pre", "hr",
            "ul", "ol", "li", "dd", "dt",
            "img",
            "a",
            "sub", "sup",
        ]
        attrs = ['alt', 'href', 'src', 'title']
        protocols= ['http', 'https', 'ftp']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
            tags=allowed_tags, attributes=attrs, protocols=protocols, strip=True))

db.event.listen(Comment.body, 'set', Comment.on_changed_body)


class Vote(db.Model):
    __talename__ = 'vote'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'), index=True)
    user: so.Mapped['User'] = so.relationship(back_populates='votes')
    post_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, nullable=True, index=True)
    comment_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, nullable=True)
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))

    def del_self(self):
        db.session.execute(sa.delete(Vote).where(Vote.id == self.id))


class Tag(db.Model):
    __tablename__ = 'tag'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    posts: so.Mapped[List['Post']] = so.relationship(secondary=tags, back_populates='tags')

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(name) <= 30),
    )

    def del_self(self):
        db.session.execute(tags.delete().where(tags.c.tag_id == self.id))
        db.session.execute(sa.delete(Tag).where(Tag.id == self.id))

    @staticmethod
    def query_tag(name):
        return db.first_or_404(sa.select(Tag).where(Tag.name == name))


class FlagReason(Enum):
    NSFW = 1
    SPAM = 2
    VIOLENT = 3


class Flag(db.Model):
    __tablename__ = 'flag'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    reason: so.Mapped[int] = so.mapped_column(default=0)
    user_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'), index=True)
    user: so.Mapped['User'] = so.relationship(back_populates='flags')
    post_id: so.Mapped[int] = so.mapped_column(sa.BigInteger)
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))

    def del_self(self):
        db.session.execute(sa.delete(Flag).where(Flag.id == self.id))


class Conversation(db.Model):
    __tablename__ = 'conversation'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    mailbox: so.Mapped[int] = so.mapped_column(sa.BigInteger)
    message_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, index=True)
    sender_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, index=True)
    recipient_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, index=True)

    def del_conversation(self):
        db.session.execute(sa.delete(Conversation).where(Conversation.id == self.id))

    @staticmethod
    def query_convo(current_id, user_id):
        return db.session.execute(sa.select(Conversation.mailbox)\
        .where(((Conversation.sender_id == current_id) & (Conversation.recipient_id == user_id))\
         | ((Conversation.sender_id == user_id) & (Conversation.recipient_id == current_id)))).scalar()

    @staticmethod
    def query_message_id(current_id, user_id):
        return db.session.execute(sa.select(Conversation.message_id)\
        .where(((Conversation.sender_id == current_id) & (Conversation.recipient_id == user_id))\
         | ((Conversation.sender_id == user_id) & (Conversation.recipient_id == current_id)))).scalars()

    @staticmethod
    def query_mailbox_id():
        return db.session.execute(sa.select(sa.func.max(Conversation.message_id))\
        .where((Conversation.sender_id == current_user.id)\
         | (Conversation.recipient_id == current_user.id)).group_by(Conversation.mailbox)).scalars()


class Message(db.Model):
    __tablename__ = 'message'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    sender_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'))
    sender: so.Mapped['User'] = so.relationship(foreign_keys='Message.sender_id', back_populates='messages_sent')
    recipient_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'))
    recipient: so.Mapped['User'] = so.relationship(foreign_keys='Message.recipient_id', back_populates='messages_received')
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')
    body: so.Mapped[str] = so.mapped_column(sa.LargeBinary)
    photos: so.Mapped[str] = so.mapped_column(sa.LargeBinary, nullable=True)
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc), index=True)
    read_timestamp: so.Mapped[datetime] = so.mapped_column(nullable=True)

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
    )

    def get_url(self):
        if self.photos:
            url = json.loads(Message.decrypt(self.photos))['link']
            return Photo.get_url(url.removeprefix(f"{Config.SPACES_URL}/message-pics/"))

    def get_photos(self):
        if self.photos:
            return json.loads(Message.decrypt(self.photos))

    def _del_photos(self):
        photos = json.loads(Message.decrypt(self.photos)) if self.photos else None
        if photos:
            p = photos['link']
            if f"niitii-spaces" in p:
                name = p.removeprefix(f"{Config.SPACES_URL}/message-pics/")
                Photo.del_object('message-pics', name)

    def del_message(self):
        self._del_photos()
        db.session.execute(sa.delete(Message).where(Message.id == self.id))

# sa.LargeBinary is to work with Fernet encrypt-decrypt
# encode() converts str to bytes with b''. current_app.config['MESSAGE_KEY'].encode() gets an "app.context" error
    key = Config.MESSAGE_KEY.encode()

    @staticmethod
    def encrypt(value):
        return Fernet(Message.key).encrypt(value.encode())

    @staticmethod
    def decrypt(value):
        return Fernet(Message.key).decrypt(value).decode()

    @staticmethod
    def query_message(id, scalar=False):
        if scalar:
            return db.session.execute(sa.select(Message).where(Message.id == id)).scalar()
        else:
            return db.first_or_404(sa.select(Message).where(Message.id == id))
            
    @staticmethod
    def query_message_list(id_list):
        return db.session.execute(sa.select(Message).where(Message.id.in_(id_list))\
        .order_by(Message.id.asc())).scalars()

    @staticmethod
    def mark_read(id_list):
        messages = db.session.execute(sa.select(Message).where(Message.id.in_(id_list))\
        .order_by(Message.id.asc())).scalars()

        for m in messages:
            if m.recipient_id == current_user.id and not m.read_timestamp:
                m.read_timestamp = datetime.now(timezone.utc)


class Notification(db.Model):
    __tablename__ = 'notification'
    id: so.Mapped[int] = so.mapped_column(sa.BigInteger, primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.UnicodeText, index=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'))
    user: so.Mapped['User'] = so.relationship(back_populates='notifications')
    payload_json: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    item_id: so.Mapped[int] = so.mapped_column(sa.BigInteger)
    item_type: so.Mapped[str] = so.mapped_column(sa.UnicodeText, index=True)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')
    utc_offset: so.Mapped[float] = so.mapped_column(sa.Float(precision=24), default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc), index=True)

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(name) <= 100),
        sa.CheckConstraint(sa.func.char_length(item_type) <= 32),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
    )

    def get_payload(self):
        return json.loads(str(self.payload_json))

    def put_payload(self, payload):
        self.payload_json = json.dumps(payload)
        
    def del_self(self):
        db.session.execute(sa.delete(Notification).where(Notification.id == self.id))


class Photo():
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

    def send_object(bucket, name, upload=False, **kwargs):
# Boto3 Session objects are not thread-safe, sharing a single Session across multiple threads can lead to unexpected errors or inconsistent behavior.
# instantiate a new boto3.Session() within each thread's execution context.
        session = boto3.session.Session()
        client = session.client('s3',
            endpoint_url = Config.SPACES_URL,
            region_name = Config.SPACES_REGION,
            aws_access_key_id = Config.SPACES_KEY,
            aws_secret_access_key = Config.SPACES_SECRET)

        if upload:
            client.put_object(
                Bucket=bucket,
                Key=f"{name}",
                Body=kwargs['body'],
                ACL=kwargs['acl'],
                Metadata={
                    'x-amz-meta-Author': f"{kwargs['author']}",
                    'x-amz-meta-Timestamp': f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
                    'x-amz-meta-ReferenceId': f"{kwargs['ref_id']}",
                }
            )
        else:
            client.delete_object(
                Bucket=bucket,
                Key=f"{name}",
            )

#https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html
    def resize_compress(f):
        ext = f.filename.split('.')[-1]
        buf = BytesIO()
        try:
            img = Image.open(f)
            width = 1920 if img.width > 1920 else img.width
            height = 1080 if img.height > 1080 else img.height
            img.thumbnail((width, height), Image.Resampling.LANCZOS)
            img.save(buf, format= 'JPEG' if ext.lower() == 'jpg' else ext.upper(), optimize=True, quality=85)
            buf.seek(0)
            return buf
        except:
            return f

#https://docs.digitalocean.com/reference/api/spaces-api/
#https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html
    def upload_object(bucket, name, f, acl, ref_id=0):
        author = f'{current_user.username}' if acl != 'private' else None

        if f.filename.split('.')[-1] in ['jpg', 'jpeg', 'png']:
            body = Photo.resize_compress(f)
        else:
            body = f

# body.read() passes content as bytes to prevent error
# botocore.exceptions.HTTPClientError: An HTTP Client raised an unhandled exception: I/O operation on closed file.
        kwargs = {'body':body.read(), 'acl':acl, 'author':author, 'ref_id':ref_id}
        
        Thread(target=Photo.send_object, args=(bucket, name, True), kwargs=kwargs).start()

    def del_object(bucket, name):
        Thread(target=Photo.send_object, args=(bucket, name)).start()

    def get_url(name):
# func cannot be threaded due to pending page load
        session = boto3.session.Session()
        client = session.client('s3',
            endpoint_url = Config.SPACES_URL,
            region_name = Config.SPACES_REGION,
            aws_access_key_id = Config.SPACES_KEY,
            aws_secret_access_key = Config.SPACES_SECRET)

        return client.generate_presigned_url('get_object',
                                            Params={
                                                'Bucket': 'message-pics',
                                                'Key': name
                                            },
                                            ExpiresIn = 60,)


class Chatii():
    rooms = {}

    def generate_room_code(length):
        while True:
            code = ''
            for _ in range(length):
                # Exclude letters "L, O"
                code += SystemRandom().choice('ABCDEFGHIJKMNPQRSTUVWXYZ' + digits)
                
            if code not in Chatii.rooms:
                break
                
        return code


class Task(db.Model):
    __tablename__ = 'task'
#    id primary key is not integer. Uses job identifier from RQ for key
    id: so.Mapped[str] = so.mapped_column(sa.UnicodeText, primary_key=True)
#    name is RQ task's fully qualified name
    name: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
#    for showing to users
    description: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
#   relationship to user requesting the task
    user_id: so.Mapped[int] = so.mapped_column(sa.BigInteger, sa.ForeignKey('user.id'))
#   task completion state
    user: so.Mapped['User'] = so.relationship(back_populates='tasks')
    complete: so.Mapped[bool] = so.mapped_column(default=False)
    
    __table__args = (
        sa.CheckConstraint(sa.func.char_length(id) <= 64),
        sa.CheckConstraint(sa.func.char_length(name) <= 100),
        sa.CheckConstraint(sa.func.char_length(description) <= 200),
    )

#   loads RQ Job instance from a given task id, which comes from Task model. Job.fetch() loads Job instance from data in Redis
    def get_rq_job(self):
        try:
            rq_job = rq.job.Job.fetch(self.id, connection=current_app.redis)
        except (redis.exceptions.RedisError, rq.exceptions.NoSuchJobError):
            return None
        return rq_job

#    returns progress percentage of task. If job id does not exist in RQ queue then method assumes that job finished and data expired after 500s.
#    if job has no info in meta then method assumes that job is scheduled but did not star, progress is 0 
    def get_progress(self):
        job = self.get_rq_job()
        return job.meta.get('progress', 0 ) if job is not None else 100
     
