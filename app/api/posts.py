from app import db
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request
from app.decorators import permission_required
from app.models import Post, Permission
from flask import jsonify, request, g, url_for, current_app
import sqlalchemy as sa


@bp.route('/post/')
@token_auth.login_required
def get_posts():
    query = sa.select(Post).order_by(Post.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    posts = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('bp.get_posts', page=page-1)
    next = None
    if pagination.has_next:
        next = url_for('bp.get_posts', page=page+1)
    return jsonify({
        'posts': [post.to_json() for post in posts],
        'prev': prev,
        'next': next,
        'count': pagination.total
    })


@bp.route('/post/<int:id>')
@token_auth.login_required
def post(id):
    post = Post.query.get_or_404(id)
    return jsonify(post.to_json())


@bp.route('/post/', methods=['POST'])
@token_auth.login_required
@permission_required('WRITE')
def new_post():
    post = Post.from_json(request.json)
    post.author = g.current_user
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_json()), 201, {'Location': url_for('bp.post', id=post.id)}


@bp.route('/post/<int:id>', methods=['PUT'])
@token_auth.login_required
@permission_required('WRITE')
def edit_post(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if g.current_user != post.author and not g.current_user.can('MODERATE'):
        return bad_request('Invalid permissions')
    post.body = request.json.get('body', post.body)
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_json())
