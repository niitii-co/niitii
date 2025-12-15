from app import db
from app.models import User
from app.api.errors import error_response
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import sqlalchemy as sa


basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()


@basic_auth.verify_password
def verify_password(username, password):
    user = db.session.execute(sa.select(User).where(User.username == username)).scalar()
    if user and user.check_password(password):
        return user


@basic_auth.error_handler
def basic_auth_error(status):
    return error_response(status)


@token_auth.verify_token
def verify_token(token):
    return User.check_token(token) if token else None


@token_auth.error_handler
def token_auth_error(status):
    return error_response(status)
