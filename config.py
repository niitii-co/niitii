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
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')        
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_SUBJECT_PREFIX = '[Niitii]'    
    MAIL_SENDER = 'no_reply@niitii.com'
    ADMIN = json.loads(os.environ['ADMIN'])
    LANGUAGES = ['en', 'es', 'fr', 'pt']
    MESSAGE_KEY = os.environ.get('MESSAGE_KEY')
    ALLOWED_EXTENSIONS = {'gif', 'jpg', 'jpeg', 'jfif', 'pjpeg', 'pjp', 'png', 'apng', 'avif', 'svg', 'webp'}
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    BUCKET = 'niitii-spaces'
    SPACES_REGION = 'nyc3'
    SPACES_URL = 'https://niitii-spaces.nyc3.digitaloceanspaces.com'
    SPACES_CDN_URL = 'https://niitii-spaces.nyc3.cdn.digitaloceanspaces.com'    
    SPACES_KEY = os.environ.get('SPACES_KEY')
    SPACES_SECRET = os.environ.get('SPACES_SECRET')
    POSTS_PER_PAGE = 20
    COMMENTS_PER_PAGE = 30
    FOLLOWS_PER_PAGE = 50
    SQLALCHEMY_TRACK_MODIFICATIONS = False    
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
