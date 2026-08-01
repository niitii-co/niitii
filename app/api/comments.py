from app import db
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request
from app.decorators import permission_required
from app.models import Post, Permission, Comment
from flask import jsonify, request, g, url_for, current_app
import sqlalchemy as sa


@bp.route('/comments/')
@token_auth.login_required
def get_comments():
    query = sa.select(Comment).order_by(Comment.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    comments = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('api.get_comments', page=page-1)
    next = None
    if pagination.has_next:
        next = url_for('api.get_comments', page=page+1)
    return jsonify({
        'comments': [comment.to_json() for comment in comments],
        'prev': prev,
        'next': next,
        'count': pagination.total
    })


@bp.route('/comments/<int:id>')
@token_auth.login_required
def comment(id):
    comment = db.get_or_404(Comment, id)
    return jsonify(comment.to_json())


@bp.route('/posts/<int:id>/comments/')
@token_auth.login_required
def post_comments(id):
    post = db.get_or_404(Post, id)
    query = post.comments.select().order_by(Comment.timestamp.asc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    comments = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('api.post_comments', id=id, page=page-1)
    next = None
    if pagination.has_next:
        next = url_for('api.post_comments', id=id, page=page+1)
    return jsonify({
        'comments': [comment.to_json() for comment in comments],
        'prev': prev,
        'next': next,
        'count': pagination.total
    })


@bp.route('/posts/<int:id>/comments/', methods=['POST'])
@token_auth.login_required
@permission_required('COMMENT')
def new_post_comment(id):
    post = db.get_or_404(Post, id)
    comment = Comment.from_json(request.json)
    comment.author = g.current_user
    comment.post = post
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_json()), 201, \
        {'Location': url_for('api.comment', id=comment.id)}
