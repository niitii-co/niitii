import os
from dotenv import load_dotenv

# Get the path to the directory this file is in
basedir = os.path.abspath(os.path.dirname(__file__))

# Connect the path with your '.env' file name
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '').replace(
        'postgres://', 'postgresql://') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')        
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_SUBJECT_PREFIX = '[Niitii]'    
    MAIL_SENDER = os.environ.get('MAIL_SENDER')  
    NIITII_ADMIN = os.environ.get('NIITII_ADMIN')    
    ADMIN = os.environ.get('ADMIN')
    LANGUAGES = ['en', 'es', 'fr', 'pt']
    MESSAGE_KEY = os.environ.get('MESSAGE_KEY')
    ALLOWED_EXTENSIONS = {'gif', 'jpg', 'jpeg', 'jfif', 'pjpeg', 'pjp', 'png', 'apng', 'avif', 'svg', 'webp'}
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    BUCKET = 'niitii-spaces'
    SPACES_REGION = os.environ.get('SPACES_REGION')
    SPACES_URL = os.environ.get('SPACES_URL')
    SPACES_KEY = os.environ.get('SPACES_KEY')
    SPACES_SECRET = os.environ.get('SPACES_SECRET')
    POSTS_PER_PAGE = 20
    COMMENTS_PER_PAGE = 30
    FOLLOWS_PER_PAGE = 50
    SQLALCHEMY_TRACK_MODIFICATIONS = False    
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # email errors to the administrators
        # log to syslog
        import logging
        from logging.handlers import SMTPHandler
        from logging.handlers import SysLogHandler        
        credentials = None
        secure = None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()
        mail_handler = SMTPHandler(
            mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
            fromaddr=cls.MAIL_SENDER,
            toaddrs=[cls.ADMIN],
            subject=cls.MAIL_SUBJECT_PREFIX + ' Application Error',
            credentials=credentials,
            secure=secure)
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)
        
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.INFO)
        app.logger.addHandler(syslog_handler)


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
