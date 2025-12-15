from config import Config
from customHandler import CustomHandler
from flask import Flask, request, current_app
from flask_babel import Babel, lazy_gettext as _l
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_moment import Moment
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
from logging.handlers import SMTPHandler, RotatingFileHandler
from redis import Redis
import logging
import os
import rq


def get_locale():
    return request.accept_languages.best_match(current_app.config['LANGUAGES'])


babel = Babel()
db = SQLAlchemy()
login = LoginManager()
login.login_view = 'auth.login'
login.login_message = _l('login to access')
mail = Mail()
migrate = Migrate()
moment = Moment()
csrf = CSRFProtect()
socketio = SocketIO()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    babel.init_app(app, locale_selector=get_locale)
    db.init_app(app)
    login.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    moment.init_app(app)
    csrf.init_app(app)
    socketio.init_app(app, cors_allowed_origins=app.config['CORS_ALLOWED_ORIGINS'], max_http_buffer_size=app.config['MAX_HTTP_BUFFER_SIZE'])
    app.redis = Redis.from_url(app.config['REDIS_URL'])
    app.task_queue = rq.Queue('niitii-tasks', connection=app.redis)

    from app.errors import bp as errors_bp
    app.register_blueprint(errors_bp)

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.cli import bp as cli_bp
    app.register_blueprint(cli_bp)

    from app.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    if not app.debug and not app.testing:
        mail_handler = CustomHandler(
            url = app.config['MAIL_API_URL'],
            token = app.config['MAIL_PASSWORD'],
            sender = app.config['MAIL_SENDER'],
            recipient = app.config['ADMIN']
        )
        
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)
# STMP may be blocked by Hosting provider
#        if app.config['MAIL_SERVER']:
#            mail_handler = SMTPHandler(
#                mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
#                fromaddr=app.config['MAIL_SENDER'],
#                toaddrs=app.config['ADMIN'],
#                subject='niitii Failure',
#                credentials=(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']),
#                secure=())
#            mail_handler.setLevel(logging.ERROR)
#            app.logger.addHandler(mail_handler)
    else:    
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/app.log',
                                           maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('niitii startup')

    return app


from app import models
