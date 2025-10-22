import os
import json
from dotenv import load_dotenv

# Get the path to the directory this file is in
basedir = os.path.abspath(os.path.dirname(__file__))

# Connect the path with your '.env' file name
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '').replace(
        'postgres://', 'postgresql://')
#    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
    MAIL_API_URL = os.environ.get('MAIL_API_URL')
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_SUBJECT_PREFIX = os.environ.get('MAIL_SUBJECT_PREFIX')
    MAIL_SENDER = os.environ.get('MAIL_SENDER')
    ADMIN = json.loads(os.environ['ADMIN'])
    LANGUAGES = json.loads(os.environ['LANGUAGES'])
    MESSAGE_KEY = os.environ.get('MESSAGE_KEY')
    ALLOWED_EXTENSIONS = {'gif', 'jpg', 'jpeg', 'jfif', 'pjpeg', 'pjp', 'png', 'apng', 'avif', 'svg', 'webp'}
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH'))
    BUCKET = os.environ.get('BUCKET')
    SPACES_REGION = os.environ.get('SPACES_REGION')
    SPACES_URL = os.environ.get('SPACES_URL')
    SPACES_CDN_URL = os.environ.get('SPACES_CDN_URL')
    SPACES_KEY = os.environ.get('SPACES_KEY')
    SPACES_SECRET = os.environ.get('SPACES_SECRET')
    POSTS_PER_PAGE = int(os.environ.get('POSTS_PER_PAGE'))
    COMMENTS_PER_PAGE = int(os.environ.get('COMMENTS_PER_PAGE'))
    FOLLOWS_PER_PAGE = int(os.environ.get('FOLLOWS_PER_PAGE'))
    CORS_ALLOWED_ORIGINS = json.loads(os.environ['CORS_ALLOWED_ORIGINS'])
    MAX_HTTP_BUFFER_SIZE = int(os.environ.get('MAX_HTTP_BUFFER_SIZE'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
