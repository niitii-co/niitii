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
from sqlalchemy.ext.hybrid import hybrid_property
from string import digits
from time import time
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
# db.paginate is a Flask-SQLAlchemy methods
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
    sa.Column('follower_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    sa.Column('followed_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
)


class Permission(Enum):
    READ = 1
    COMMENT = 2
    MESSAGE = 4
    WRITE = 8
    MODERATE = 16
    ADMIN = 32
    ROOT_ADMIN = 64


class User(PaginatedAPIMixin, UserMixin, db.Model):
    __tablename__ = 'user'
    id: so.Mapped[int] = so.mapped_column(primary_key=True, default=SystemRandom().randrange(1000000000, 9999999999, 1))
    username: so.Mapped[str] = so.mapped_column(sa.UnicodeText, index=True, unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.UnicodeText, index=True, unique=True)
    contact_email: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    password_hash: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    confirmed: so.Mapped[bool] = so.mapped_column(default=False)
    verified: so.Mapped[bool] = so.mapped_column(default=False)
    disabled: so.Mapped[bool] = so.mapped_column(default=False)
    permission: so.Mapped[int] = so.mapped_column(default=Permission.WRITE.value)
    mfa_enabled: so.Mapped[bool] = so.mapped_column(default=False)
    otp_secret: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)    
    admin_token: so.Mapped[int] = so.mapped_column(nullable=True)
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
    utc_offset: so.Mapped[int] = so.mapped_column(default=0)
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
        back_populates='followers', cascade='all, delete', passive_deletes=True)
    followers: so.WriteOnlyMapped['User'] = so.relationship(
        secondary=follows, primaryjoin=(follows.c.followed_id == id),
        secondaryjoin=(follows.c.follower_id == id),
        back_populates='following', cascade='all, delete', passive_deletes=True)
    messages_sent: so.WriteOnlyMapped['Message'] = so.relationship(foreign_keys='Message.sender_id', back_populates='sender', cascade='all, delete', passive_deletes=True)
    messages_received: so.WriteOnlyMapped['Message'] = so.relationship(foreign_keys='Message.recipient_id', back_populates='recipient', cascade='all, delete', passive_deletes=True)
    posts: so.WriteOnlyMapped['Post'] = so.relationship(back_populates='author', cascade='all, delete', passive_deletes=True)
    comments: so.WriteOnlyMapped['Comment'] = so.relationship(back_populates='author', cascade='all, delete', passive_deletes=True)
    votes: so.WriteOnlyMapped['Vote'] = so.relationship(back_populates='user', cascade='all, delete', passive_deletes=True)
    flags: so.WriteOnlyMapped['Flag'] = so.relationship(back_populates='user', cascade='all, delete', passive_deletes=True)
    notifications: so.WriteOnlyMapped['Notification'] = so.relationship(back_populates='user', cascade='all, delete', passive_deletes=True)
    tasks: so.WriteOnlyMapped['Task'] = so.relationship(back_populates='user', cascade='all, delete', passive_deletes=True)

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(username) <= 32),
        sa.CheckConstraint(sa.func.char_length(email) <= 128),
        sa.CheckConstraint(sa.func.char_length(contact_email) <= 128),
        sa.CheckConstraint(sa.func.char_length(about_me) <= 1024),
        sa.CheckConstraint(sa.func.char_length(photo) <= 256),
        sa.CheckConstraint(sa.func.char_length(song) <= 256),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
        sa.CheckConstraint(sa.func.char_length(phone) <= 64),
        sa.CheckConstraint(sa.func.char_length(location) <= 128),
        sa.CheckConstraint(sa.func.char_length(label) <= 32),
        sa.CheckConstraint(sa.func.char_length(banner_flag) <= 8),
        sa.CheckConstraint(sa.func.char_length(token) <= 32),
    )


    def __repr__(self):
        return f'<User "{self.username}">'

    def is_moderator(self):
        return self.permission == Permission.MODERATE.value

    def is_admin(self):
        return self.permission == Permission.ADMIN.value

    def is_site_admin(self):
        return self.permission == Permission.ROOT_ADMIN.value

    def can(self, key):
        return self.permission >= Permission[key].value

    def get_permission(self):
        return Permission(self.permission).name

    def set_permission(self, key):
        if key == 'MODERATE' and not self.confirmed:
            pass
        elif key == "ADMIN" and not self.confirmed and not self.verified:
            pass
        elif key == "ROOT_ADMIN" and not self.verified and not self.mfa_enabled:
            pass
        else:
            self.permission = Permission[key].value

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_admin_token(self):
        if self.mfa_enabled:
            self.admin_token = SystemRandom().randrange(100000, 999999, 1)

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

#    static method has no access to (self). static methods do not receive the class as a first argument.
    @staticmethod
    def confirm_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['confirm']
        except:
            return None
        return db.session.get(User, id)

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

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return None
        return db.session.get(User, id)

    def follow(self, user):
        if not self.is_following(user):
            self.following.add(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)

    def is_following(self, user):
        query = self.following.select().where(User.id == user.id)
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

    def new_message_count(self):
        last_read_time = self.last_message_read_time or datetime(1900, 1, 1)
        query = self.messages_received.select().where(Message.timestamp > last_read_time)
        return db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()

    def new_notification_count(self):
        query = self.notifications.select().where((Notification.name != "new_message_count") & (Notification.name != "ping_count") & (Notification.name != "new_ping"))
        return db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()

    def ping_count(self):
        query = self.notifications.select().where(Notification.name == 'new_ping')
        return db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()

    def new_feed_count(self):
        last_read_time = self.last_feed_read_time - timedelta(days=5) or datetime(1900, 1, 1)
        query = self.following_posts().where(Post.author != current_user, Post.timestamp > last_read_time)
        return db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()

    def add_notification(self, name, payload, item_id, item_type):
        db.session.add(Notification(user=self, name=name, payload_json=json.dumps(payload), item_id=item_id, item_type=item_type))
        
    def update_notification(self, name, payload):
        db.session.execute(self.notifications.update().where(Notification.name == name).values(payload_json=json.dumps(payload), timestamp=datetime.now(timezone.utc)))

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

#   check if token is invalid or expired
    @staticmethod
    def check_token(token):
        user = db.session.execute(sa.select(User).where(User.token == token)).scalar()
        if user is None or user.token_expiration.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            return None
        return user

    def delete_photo(self):
        if f"{Photo.SPACES_URL}/profile-pics/" in self.photo:
            name = self.photo.removeprefix(f"{Photo.SPACES_URL}/profile-pics/")
            Photo.delete_object('profile-pics', name)
            self.photo = None


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


tags = sa.Table(
    'tags',
    db.metadata,
    sa.Column('post_id', sa.Integer, sa.ForeignKey('post.id', ondelete='CASCADE'), primary_key=True),
    sa.Column('tag_id', sa.Integer, sa.ForeignKey('tag.id', ondelete='CASCADE'), primary_key=True)
)


class Post(db.Model):
    __tablename__ = 'post'
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    title: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    body: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    body_html: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
    author: so.Mapped['User'] = so.relationship(back_populates='posts')
    votes: so.Mapped[int] = so.mapped_column(index=True, default=0)
    flags: so.Mapped[int] = so.mapped_column(default=0)
    comments: so.Mapped[int] = so.mapped_column(index=True, default=0)
    pin_comments: so.Mapped[int] = so.mapped_column(default=0)
    disable_comments: so.Mapped[bool] = so.mapped_column(default=False)
    nsfw: so.Mapped[bool] = so.mapped_column(default=False)
    label: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    locked: so.Mapped[bool] = so.mapped_column(default=False)
    photos: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    editor: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    utc_offset: so.Mapped[int] = so.mapped_column(default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))
    edit_timestamp: so.Mapped[datetime] = so.mapped_column(nullable=True)
    tags: so.Mapped[List['Tag']] = so.relationship(secondary=tags, back_populates='posts', cascade='all, delete', passive_deletes=True)

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(title) <= 256),
        sa.CheckConstraint(sa.func.char_length(body) <= 4096),
        sa.CheckConstraint('pin_comments <= 2'),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
        sa.CheckConstraint(sa.func.char_length(label) <= 32),
    )


    def __repr__(self):
        return f'<Post "{self.body}">'

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

    def votes_count(self):
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
        return sa.select(Comment).where(Comment.post_id == self.id).order_by(Comment.pinned.desc(), Comment.votes.desc(), Comment.timestamp.desc())

    def get_tags(self):
        post_tags = []
        for tag in self.tags:
            post_tags.append(tag.name)
        return post_tags
#        return sa.select(Tag).where(Tag.posts == self.tags)

    def delete_comments(self):
        return db.session.execute(sa.delete(Comment).where(Comment.post_id == self.id))

    def delete_flags(self):
        return db.session.execute(sa.delete(Flag).where(Flag.post_id == self.id))

    def delete_votes(self):
        return db.session.execute(sa.delete(Vote).where(Vote.post_id == self.id))

    def delete_photos(self):
        photos = json.loads(self.photos) if self.photos else None
        if photos:
            for p in photos['link']:
                if f"{Photo.SPACES_URL}/post-pics/" in p:
                    Photo.delete_object('post-pics', p.removeprefix(f"{Photo.SPACES_URL}/post-pics/"))

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
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    body_html: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    disabled: so.Mapped[bool] = so.mapped_column(default=False)
    pinned: so.Mapped[bool] = so.mapped_column(default=False)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
    author: so.Mapped['User'] = so.relationship(back_populates='comments')
    votes: so.Mapped[int] = so.mapped_column(default=0)
    post_id: so.Mapped[int] = so.mapped_column()
    parent_id: so.Mapped[int] = so.mapped_column(nullable=True)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')    
    utc_offset: so.Mapped[int] = so.mapped_column(default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(body) <= 1024),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
    )


    def __repr__(self):
        return f'<Comment "{self.body}">'

    def votes_count(self):
        query= sa.select(Vote).where(Vote.comment_id == self.id)
        count = db.session.execute(sa.select(sa.func.count()).select_from(query.subquery())).scalar()
        self.votes = count
        return count

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
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
    user: so.Mapped['User'] = so.relationship(back_populates='votes')
    post_id: so.Mapped[int] = so.mapped_column(nullable=True)
    comment_id: so.Mapped[int] = so.mapped_column(nullable=True)
    utc_offset: so.Mapped[int] = so.mapped_column(default=0)    
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))


#https://docs.sqlalchemy.org/en/20/core/selectable.html#sqlalchemy.sql.expression.TableClause.columns
#https://docs.sqlalchemy.org/en/20/core/selectable.html#sqlalchemy.sql.expression.TableClause.delete
class Tag(db.Model):
    __tablename__ = 'tag'
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    posts: so.Mapped[List['Post']] = so.relationship(secondary=tags, back_populates='tags', passive_deletes=True)

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(name) <= 32),
    )

    def __repr__(self):
        return f'<Tag "{self.name}">'


class FlagReason(Enum):
    ADULT = 1
    SPAM = 2
    VIOLENT = 3


class Flag(db.Model):
    __tablename__ = 'flag'
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    reason: so.Mapped[int] = so.mapped_column(default=0)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
    user: so.Mapped['User'] = so.relationship(back_populates='flags')
    post_id: so.Mapped[int] = so.mapped_column()

    def __repr__(self):
        return f'<Flag "{self.reason}">'


class Conversation(db.Model):
    __tablename__ = 'conversation'
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    mailbox: so.Mapped[int] = so.mapped_column()
    message_id: so.Mapped[int] = so.mapped_column()
    sender_id: so.Mapped[int] = so.mapped_column()
    recipient_id: so.Mapped[int] = so.mapped_column()

    def __repr__(self):
        return f'<Mailbox "{self.mailbox}">'


class Message(db.Model):
    __tablename__ = 'message'
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    sender_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
    sender: so.Mapped['User'] = so.relationship(foreign_keys='Message.sender_id', back_populates='messages_sent')
    recipient_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
    recipient: so.Mapped['User'] = so.relationship(foreign_keys='Message.recipient_id', back_populates='messages_received')
#    Store as (BLOB or BYTEA) to work with Fernet encrypt-decrypt
    body: so.Mapped[str] = so.mapped_column(sa.LargeBinary)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')    
    photos: so.Mapped[str] = so.mapped_column(sa.UnicodeText, nullable=True)
    utc_offset: so.Mapped[int] = so.mapped_column(default=0)    
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(body) <= 1024),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
    )

    def __repr__(self):
        return f'<Message ID - "{self.id}">'

    def get_url(self):
        photos = json.loads(self.photos)['link']
        return Photo.get_url(photos.removeprefix(f"{Photo.SPACES_URL}/message-pics/"))

    def get_photos(self):
        if self.photos:
            return json.loads(self.photos)

    def delete_photos(self):
        photos = json.loads(self.photos) if self.photos else None
        if photos:
            for p in photos['link']:
                if f"{Photo.SPACES_URL}/post-pics/" in p:
                    name = p.removeprefix(f"{Photo.SPACES_URL}/message-pics/")
                    Photo.delete_object('message-pics', name)
# encode() converts str to bytes with b''. current_app.config['MESSAGE_KEY'].encode() gets an "app.context" error
    key = Config.MESSAGE_KEY.encode()

    def encrypt(value):
        return Fernet(Message.key).encrypt(value.encode())

    def decrypt(self):
        return Fernet(Message.key).decrypt(self.body).decode()


class Notification(db.Model):
    __tablename__ = 'notification'
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    user: so.Mapped['User'] = so.relationship(back_populates='notifications')
    payload_json: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    item_id: so.Mapped[int] = so.mapped_column()
    item_type: so.Mapped[str] = so.mapped_column(sa.UnicodeText)
    language: so.Mapped[str] = so.mapped_column(sa.UnicodeText, default='en-US')
    utc_offset: so.Mapped[int] = so.mapped_column(default=0)
    timestamp: so.Mapped[datetime] = so.mapped_column(default=lambda: datetime.now(timezone.utc))

    __table__args = (
        sa.CheckConstraint(sa.func.char_length(name) <= 128),
        sa.CheckConstraint(sa.func.char_length(item_type) <= 32),
        sa.CheckConstraint(sa.func.char_length(language) <= 16),
    )

    def get_payload(self):
        return json.loads(str(self.payload_json))

    def update_payload(self, payload):
        self.payload_json = json.dumps(payload)


class Photo():
    SPACES_URL = Config.SPACES_URL
    SPACES_CDN_URL = Config.SPACES_CDN_URL


    session = boto3.session.Session()
    client = session.client('s3',
        endpoint_url = Config.SPACES_URL,
        region_name = Config.SPACES_REGION,
        aws_access_key_id = Config.SPACES_KEY,
        aws_secret_access_key = Config.SPACES_SECRET)

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']
       
#    https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html
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
    def upload_object(bucket, name, f, acl):
        if f.filename.split('.')[-1] in ['jpg', 'jpeg', 'png']:
            body = Photo.resize_compress(f)
        else:
            body = f
       
        try:
            Photo.client.put_object(
                Bucket=bucket,
                Key=f"{name}",
                Body=body,
                ACL= acl,
                Metadata={
#                    Defines metadata tags
#                    f' fixes error: int' object has no attribute 'encode'
                    'x-amz-meta-author': f'{current_user.id}'
                }
            )
            return True
        except:
            return False

    def delete_object(bucket, name):
        try:
            Photo.client.delete_object(
                Bucket=bucket,
                Key=f"{name}",
            )
            return True
        except:
            return False

    def get_url(name):
        return Photo.client.generate_presigned_url('get_object',
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
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'))
#   task completion state
    user: so.Mapped['User'] = so.relationship(back_populates='tasks')
    complete: so.Mapped[bool] = so.mapped_column(default=False)
    
    __table__args = (
        sa.CheckConstraint(sa.func.char_length(id) <= 64),
        sa.CheckConstraint(sa.func.char_length(name) <= 128),
        sa.CheckConstraint(sa.func.char_length(description) <= 256),
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
     
