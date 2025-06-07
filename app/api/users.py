from app import db
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request
from app.models import User
from flask import request, url_for, abort
import sqlalchemy as sa


@bp.route('/users/<int:id>', methods=['GET'])
@token_auth.login_required
def get_user(id):
    return db.get_or_404(User, id).to_dict()


@bp.route('/users', methods=['GET'])
@token_auth.login_required
def get_users():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    return User.to_collection_dict(sa.select(User), page, per_page, 'api.get_users')


@bp.route('/users/<int:id>/followers', methods=['GET'])
@token_auth.login_required
def get_followers(id):
    user = db.get_or_404(User, id)
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    return User.to_collection_dict(user.followers.select(), page, per_page, 'api.get_followers', id=id)


@bp.route('/users/<int:id>/following', methods=['GET'])
@token_auth.login_required
def get_following(id): 
    user = db.get_or_404(User, id)
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    return User.to_collection_dict(user.following.select(), page, per_page, 'api.get_following', id=id)


# error code 415 (unsupported media type) if client sends content not in JSON format.
# error code 400 (bad request) if JSON content is malformed.
# errors are handled by handle_http_exception() in app/api/errors.py
# new_user=True so from accepts the password
@bp.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    if 'username' not in data or 'email' not in data or 'password' not in data:
        return bad_request('Include username, email and password')
    if db.session.execute(sa.select(User).where(User.username == data['username'])).scalar():
        return bad_request('username taken')
    if db.session.execute(sa.select(User).where(User.email == data['email'])).scalar():
        return bad_request('email taken')
    user = User()
    user.from_dict(data, new_user=True)
    db.session.add(user)
    db.session.commit()
    return user.to_dict(), 201, {'Location': url_for('api.user', id=user.id)}


@bp.route('/users/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_user(id):
    if token_auth.current_user().id != id:
        abort(403)
    user = db.get_or_404(User, id)
    data = request.get_json()
    if 'username' in data and data['username'] != user.username and db.session.execute(sa.select(User).where(User.username == data['username'])).scalar():
        return bad_request('username taken')
    if 'email' in data and data['email'] != user.email and db.session.execute(sa.select(User).where(User.email == data['email'])).scalar():
        return bad_request('email taken')
    user.from_dict(data, new_user=False)
    db.session.commit()
    return user.to_dict()
