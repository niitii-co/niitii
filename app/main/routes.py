from app import db, socketio
from app.decorators import permission_required
from app.main import bp
from app.models import User, Post, Comment, Conversation, Message, Notification, Tag, Vote, AccountPermission, Photo, Flag, FlagReason, Chatii
from config import Config
from datetime import datetime, timezone, timedelta
from flask import abort, render_template, flash, redirect, request, url_for, g, current_app, request, make_response, session, json
from flask_login import current_user, login_required
from flask_babel import _, get_locale
from flask_wtf import CSRFProtect
from flask_socketio import emit, join_room, leave_room, send
from time import time
from werkzeug.utils import secure_filename
import sqlalchemy as sa
import os
import uuid


@bp.before_app_request
def before_app_request():
    g.locale = str(get_locale())

@bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)

        db.session.commit()
    if request.method == 'POST':
        g.lang = str(request.accept_languages).split(',')[0] if request.accept_languages != '*' else 'en-US'


@bp.route('/')
@bp.route('/home')
@bp.route('/index')
def index():
    lang = str(request.accept_languages).split(',')[0] if request.accept_languages != '*' else 'en-US'
    query = Post.get_index(lang)
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    for post in pagination.items:
        if not post.can_view():
            pagination.items.remove(post)

    return render_template('index.html', title=_('Index'), posts=pagination.items, pagination=pagination)


@bp.route('/search')
def search():
    q = request.args.get('q')
    if q:
        utc_offset = request.form.get('utc_offset', 0)
        query = Post.query_search(q, utc_offset)
        pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    else:
        return redirect(request.referrer)

    return render_template('search.html', title=_('Search'), posts=pagination.items, pagination=pagination, q=q)


@bp.route('/feed')
@login_required
def feed():
    current_user.last_feed_read_time = datetime.now(timezone.utc)
    query = current_user.get_feed()
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    db.session.commit()
    return render_template('feed.html', title=_('Feed') + f" - {current_user.username}", posts=pagination.items, pagination=pagination)


@bp.route('/new-post', methods=['GET', 'POST'])
@login_required
@permission_required('WRITE')
def new_post():
    if request.method == 'POST':
        nsfw = bool(request.form.get('nsfw', False))
        disable_comments = bool(request.form.get('disable_comments', False))
        viewer = int(request.form.get('viewer'))
        utc_offset = request.form.get('utc_offset')
        post = Post(title=request.form.get('title'), body=request.form.get('body'), author=current_user, disable_comments=disable_comments, nsfw=nsfw, language=g.lang, viewer=viewer, utc_offset=utc_offset)
        db.session.add(post)
        db.session.flush()        
        form_link = request.form.getlist('add_photos')[0:5]
        photo_name = []
        photo_link = []
        p_count = 0

# form_link will return ['', '', '', '', ''] if empty. len(form_link) = 5
        if form_link[0] != '':
            for i, f in enumerate(form_link):
                if form_link[i]:
                    photo_name.append(f"photo{i + 1}")
                    photo_link.append(f)
                    p_count += 1
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})

# If the user does not select a file, the browser submits an empty file without a filename.
# Empty files will return [<FileStorage: '' ('application/octet-stream')>]
        if request.files['photo'].filename != '' and p_count < 5:
            photo_files = request.files.getlist('photo')[0:5]
            bucket = 'post-pics'
            for f in photo_files:
                if f.filename != '' and Photo.allowed_file(f.filename):
                    f.filename = secure_filename(f.filename)
# timestamp filename to prevent duplicate name overwrite
# filename start with date so name can end with filename.ext
                    name = f"{datetime.now(timezone.utc).strftime('%H%M%S-%f-')}{f.filename}"
                    Photo.upload_object(bucket, name, f, 'public-read', post.id)
                    photo_name.append(f.filename)
                    photo_link.append(f"{Config.SPACES_URL}/{bucket}/{name}")
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})

        if request.form.get('tags'):
            form_tags = request.form.get('tags').split()[0:5]
            duplicate_tags = []
            for tag in form_tags:
                if tag not in duplicate_tags:
                    duplicate_tags.append(tag)
                    new_tag = Tag(name=tag.replace('#', ''), posts=[post])
                    db.session.add(new_tag)

        db.session.commit()
        return redirect(url_for('main.index'))

    return render_template('new_post.html', title=_('New Post'))


@bp.route('/post/<int:id>')
def post(id):
    post = Post.query_post(id)
    if not post.can_view():
        return redirect(url_for('main.user', username=post.author.username))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments_count() - 1) // current_app.config['COMMENTS_PER_PAGE'] + 1
    query = post.get_comments()
    pagination = db.paginate(query, page=page, per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('post.html', title= f"{post.title} - {post.author.username}", post=post, comments=pagination.items, pagination=pagination)


@bp.route('/comment/<int:id>', methods=['POST'])
@login_required
@permission_required('COMMENT')
def comment(id):
    post = Post.query_post(id)
    if post.locked:
        return redirect(request.referrer)
    if not post.disable_comments:
        if request.form.get('pin_comment') and post.pin_comments < 2 and (current_user == post.author or current_user.can('MODERATE')):
            pinned = True
        else:
            pinned = False

        direct = bool(request.form.get('direct_comment', False))
        ghost = bool(request.form.get('ghost_comment', False))
        utc_offset = request.form.get('utc_offset')
        comment = Comment(author=current_user._get_current_object(), body=request.form.get('body'), post_id=id, user_id=current_user.id, pinned=pinned, direct=direct, ghost=ghost, language=g.lang, utc_offset=utc_offset)

        db.session.add(comment)
        db.session.flush()
        if request.form.get('direct_comment'):
            post.direct_comments_count()
        if pinned:
            post.pin_comments_count()
        post.comments_count()

        notice = db.session.execute(post.author.notifications.select().where((Notification.item_id == id) & (Notification.name == 'new_comment'))).scalar()
        sender = current_user.username if not ghost else ''
        if notice:
            payload = {"title": f"{post.title}", "body": f"{comment.body_html if comment.body_html else request.form.get('body')}", "sender":f"{sender}"}
            notice.put_payload(payload)
            notice.timestamp = datetime.now(timezone.utc)
            notice.utc_offset = utc_offset
        else:
            payload = {"title": f"{post.title}", "body": f"{request.form.get('body')}", "sender":f"{sender}"}
            post.author.add_notification(name='new_comment', payload=payload, item_id=id, item_type='comment', utc_offset=utc_offset)

        db.session.flush()
        post.author.put_notification_count()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/reply-comment/<int:id>', methods=['POST'])
@login_required
@permission_required('COMMENT')
def reply_comment(id):
    post = Post.query_post(id)
    if post.locked:
        return redirect(request.referrer)
    if not post.disable_comments:
        comment = Comment.query_comment(request.form.get('comment_id'), True)
        c_author = User.query_user(request.form.get('authorName'), True)
        if comment:
            ghost = bool(request.form.get('ghost_comment', False))
            utc_offset = request.form.get('utc_offset')
            reply = Comment(author=current_user._get_current_object(), body=request.form.get('body'), post_id=id, user_id=current_user.id, parent_id=comment.id, ghost=ghost, language=g.lang, utc_offset=utc_offset)
            sender = current_user.username if not ghost else ''

            db.session.add(reply)
            db.session.flush()
            post.comments_count()

            payload = {"title": f"{post.title}", "body": f"{request.form.get('body')}", "sender":f"{sender}"}
            c_author.add_notification(name='reply_comment', payload=payload, item_id=id, item_type='comment', utc_offset=utc_offset)

            db.session.flush()
            c_author.put_notification_count()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/vote-post/<int:id>', methods=['POST'])
@login_required
@permission_required('WRITE')
def vote_post(id):
    post = Post.query_post(id)
    vote = db.session.execute(sa.select(Vote).where((Vote.user_id == current_user.id) & (Vote.post_id == id))).scalar()

    if post.locked:
        return {
        "count": f"&#x21E7;&#xfe0e; {post.votes}",
        }
    if not vote:
        utc_offset = request.form.get('utc_offset')
        vote = Vote(user=current_user._get_current_object(), user_id=current_user.id, post_id=id, utc_offset=utc_offset)
        db.session.add(vote)
    else:
        vote.del_self()

    db.session.flush()
    count = post.vote_count()

    db.session.commit()
    return {
        "count": f"&#x21E7;&#xfe0e; {count}",
    }


@bp.route('/vote-comment/<int:id>', methods=['POST'])
@login_required
@permission_required('WRITE')
def vote_comment(id):
    post = Post.query_post(id)
    vote = db.session.execute(sa.select(Vote).where((Vote.user_id == current_user.id) & \
    (Vote.post_id == id) & (Vote.comment_id == request.form.get('input_id')))).scalar()
    comment = Comment.query_comment(request.form.get('input_id'), True)

    if post.locked:
        return {
            "count": f"&#x21E7;&#xfe0e; {comment.votes}",
        }
    if not vote:
        utc_offset = request.form.get('utc_offset')
        vote = Vote(user_id=current_user.id, post_id=id, comment_id=comment.id, utc_offset=utc_offset)
        db.session.add(vote)
    else:
        vote.del_self()

    db.session.flush()
    count = comment.vote_count()

    db.session.commit()
    return {
        "count": f"&#x21E7;&#xfe0e; {count}",
    }


@bp.route('/flag-post/<int:id>', methods=['POST'])
@login_required
def flag_post(id):
    post = Post.query_post(id)
    flag = db.session.execute(sa.select(Flag).where((Flag.user_id == current_user.id) & (Flag.post_id == id))).scalar()
    if post.locked:
        return {
            "count": f"&#x1F6A9;&#xfe0e; {post.flags}",
        }
    if not flag:
        utc_offset = request.form.get('utc_offset')
        flag = Flag(reason=FlagReason[request.form.get('flag')].value, user_id=current_user.id, post_id=id, utc_offset=utc_offset)
        db.session.add(flag)
    else:
        flag.del_self()

    db.session.flush()
    count = post.flags_count()

    db.session.commit()
    return {
        "count": f"&#x1F6A9;&#xfe0e; {count}",
    }


@bp.route('/edit-post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Post.query_post(id)

    if current_user != post.author and not current_user.can("MODERATE"):
        return redirect(request.referrer)

    if request.method == 'POST':
        post.body = request.form.get('body') if request.form.get('body') else post.body
        post.edit_timestamp = datetime.now(timezone.utc)
        post.disable_comments = bool(request.form.get('disable_comments', False))
        post.language = g.lang
        utc_offset = request.form.get('utc_offset')
        utc_time = datetime.now(timezone.utc).strftime('%Y%m%d-%H:%M')
        post.editor = f"{current_user.username}_{utc_time}_utc_{utc_offset}"
        nsfw = bool(request.form.get('nsfw', False))
        post.nsfw = nsfw
        post.viewer = int(request.form.get('viewer', 1))
        form_tags = request.form.get('tags').split()[0:5]
        bucket = 'post-pics'
        p_photos = post.get_photos()

        if current_user.can("MODERATE"):
            post.locked = bool(request.form.get('lock_post', False))
            post.label = request.form.get('label') if request.form.get('label') and request.form.get('label') != 'null' else None

        if len(form_tags) == 0:
            post.del_tags()

        if len(form_tags) > 0 and post.tags:
            post_tags = post.get_tags()

# loop body needs to reference tag.id since there will be duplicate tag.name. Only tags linked to this post are deleted
            for tag in post.tags:
                if tag.name not in form_tags:
                    tag.del_self()

# check for duplicate tags in form then add
            for tag in form_tags:
                if tag not in post_tags:
                    new_tag = Tag(name=tag.replace('#', ''), posts=[post])
                    db.session.add(new_tag)

        else:
# check for duplicate tags
            duplicate_tags = []
            for tag in form_tags:
                if tag not in duplicate_tags:
                    duplicate_tags.append(tag)
                    new_tag = Tag(name=tag.replace('#', ''), posts=[post])
                    db.session.add(new_tag)

        photo_name = p_photos['name'] if p_photos and p_photos['name'] else []
        photo_link = p_photos['link'] if p_photos and p_photos['link'] else []
        p_max = 5 - len(p_photos['link']) if p_photos and p_photos['link'] else 5
        form_photos = request.form.getlist('add_photos')[:5]

# add_photos always returns a list of length 5. Some items in the list will be ''
# p is false if ''
        if p_max <= 5 and p_photos and form_photos:
            i = len(p_photos['link'])
            for p in request.form.getlist('add_photos'):
                if p:
                    photo_name.append(f"photo{i + 1}")
                    photo_link.append(p)
                    i += 1
                    p_max += 1
            post.photos = json.dumps({"name": p_photos['name'], "link": p_photos['link'], "nsfw": nsfw})
        elif p_max <= 5 and form_photos:
            for i, p in enumerate(form_photos):
                if p:
                    photo_name.append(f"photo{i + 1}")
                    photo_link.append(p)
                    p_max += 1                    
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})


        if p_max <= 5 and request.files and request.files['photo'].filename != '':
            photo_files = request.files.getlist('photo')[0:p_max]
            for f in photo_files:
                if f.filename != '' and Photo.allowed_file(f.filename):
                    f.filename = secure_filename(f.filename)
                    name = f"{datetime.now(timezone.utc).strftime('%H%M%S-%f-')}{f.filename}"
                    Photo.upload_object(bucket, name, f, 'public-read', post.id)
                    photo_name.append(f.filename)
                    photo_link.append(f"{Config.SPACES_URL}/{bucket}/{name}")

            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})


        if request.form.getlist('del_photos'):
            for p in request.form.getlist('del_photos'):
                i = p_photos['link'].index(p)
                if "niitii-spaces" in p:
                    Photo.del_object('post-pics', p.removeprefix(f"{Config.SPACES_URL}/post-pics/"))

                del p_photos['name'][i]
                del p_photos['link'][i]

            photo_name = p_photos['name']
            photo_link = p_photos['link']

            if len(photo_name) > 0:
                post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})
            else:
                post.photos = None


        db.session.commit()
        return redirect(url_for('main.post', id=post.id))

    post_tags = " ".join(post.get_tags())

    return render_template('edit_post.html', title=_('Edit Post') + f" - {post.author.username }", post=post, tags=post_tags)


@bp.route('/del-post/<int:id>', methods=['POST'])
@login_required
def del_post(id):
    post = Post.query_post(id)

    if post.user_id == current_user.id or current_user.can("MODERATE"):
        post.del_self()

    db.session.commit()
    return redirect(url_for('main.index'))


@bp.route('/post-comment/<int:id>')
@login_required
def post_comment(id):
    post = Post.query_post(id, True)
    if current_user != post.author and not current_user.can('MODERATE'):
        return redirect(url_for('main.post', id=id))

    query = post.get_comments()
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('post_comment.html', title=_('Post Comment') + f" - {post.author.username }", post=post, comments=pagination.items, pagination=pagination)


@bp.route('/user-comment/<username>')
@login_required
def user_comment(username):
    if current_user.username != username and not current_user.can("MODERATE"):
        return redirect(url_for('main.index'))

    user = User.query_user(username)
    query = user.query_comment()
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('user_comment.html', title=_('User Comment') + f" - {user.username }", comments=pagination.items, user=user, pagination=pagination)


@bp.route('/disable-comment/<int:id>', methods=['POST'])
@login_required
def disable_comment(id):
    comment = Comment.query_comment(id)
    post = Post.query_post(comment.post_id)    

    if current_user != comment.author and current_user != post.author and not current_user.can("MODERATE"):
        return redirect(request.referrer)

    comment.disabled = True if request.form.get('submit') == 'disable' else False
    db.session.flush()
    post.comments_count()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/del-comment/<int:id>', methods=['POST'])
@login_required
def del_comment(id):
    comment = Comment.query_comment(id)
    post = Post.query_post(comment.post_id)

    if current_user != comment.author and current_user != post.author and not current_user.can("MODERATE"):
        return redirect(request.referrer)

    if comment.direct:
        post.direct_comments -= 1

    if comment.pinned:
        post.pin_comments -= 1

    if current_user != comment.author:
        post.removed_comments += 1

    post.comments -= 1
    comment.del_self()
    db.session.flush()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/tag/<name>')
def view_tag(name):
    tag = Tag.query_tag(name)
    query = Post.tag_query(name)

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    return render_template('tag.html', title=_('Tag'), posts=pagination.items, pagination=pagination, name=name)


@bp.route('/view-flagged-post')
@login_required
@permission_required('MODERATE')
def view_flagged_post():
    query = Post.query_flagged_post()

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    db.session.commit()
    return render_template('feed.html', title=_('Feed') + f" - {current_user.username}", posts=pagination.items, pagination=pagination)


@bp.route('/moderate')
@login_required
@permission_required('MODERATE')
def moderate():
    return render_template('moderate.html', title=_('Moderate'))


@bp.route('/<username>')
def user(username):
    user = User.query_user(username)
    query = user.get_posts()
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    age = (datetime.now() - user.birth).days // 365 if user.birth else None

    for post in pagination.items:
        if not post.can_view():
            pagination.items.remove(post)

    return render_template('user.html',  title=_('User') + f" - {user.username }", user=user, posts=pagination.items, pagination=pagination, age=age)


@bp.route('/ping/<username>', methods=['POST'])
@login_required
def ping(username):
    user = User.query_user(username)
    sender = f"{current_user.username}" if request.form.get('pingCheck') else ''
    payload = {"title": f"Ping", "body": f"{request.form.get('body')}", "sender":f"{sender}"}
    utc_offset = request.form.get('utc_offset')
    user.add_notification(name='new_ping', payload=payload, item_id=0, item_type='ping', utc_offset=utc_offset)
    db.session.flush()
    user.put_notification_count()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/ping-follower', methods=['POST'])
@login_required
def ping_follower():
    query = current_user.followers.select().where(User.last_seen > (datetime.now(timezone.utc) - timedelta(days=10)))
    users = db.session.execute(query).scalars()
    
    for user in users:
        sender = f"{current_user.username}"
        payload = {"title": f"Ping", "body": f"{request.form.get('body')}", "sender":f"{sender}"}
        utc_offset = request.form.get('utc_offset')        
        user.add_notification(name='new_ping', payload=payload, item_id=0, item_type='ping', utc_offset=utc_offset)
        db.session.flush()
        user.put_notification_count()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    user = User.query_user(username)
    if not user.can_view():
        return redirect(url_for('main.user', username=user.username))
# Cannot follow self
    if user is None or user == current_user:
        return redirect(request.referrer)
    current_user.follow(user)

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    user = User.query_user(username)
# Cannot unfollow self
    if user is None or user == current_user:
        return redirect(request.referrer)

    if request.form.get('submit') == 'unfollow':
        current_user.unfollow(user)
    else:
        user.unfollow(current_user)

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/follower/<username>')
def follower(username):
    user = User.query_user(username)
    if not user.can_view():
        return redirect(url_for('main.user', username=user.username))

    query = user.followers.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)

    return render_template('follower.html',  title=_('Follower') + f" - {user.username }", users=pagination.items, user=user, pagination=pagination)


@bp.route('/following/<username>')
def following(username):
    user = User.query_user(username)
    if not user.can_view():
        return redirect(url_for('main.user', username=user.username))

    query = user.following.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)

    return render_template('edit_following.html',  title=_('Following') + f" - {user.username }", users=pagination.items, user=user, pagination=pagination)


@bp.route('/edit-follower', methods=['GET', 'POST'])
@login_required
def edit_follower():
    if request.method == 'POST':
        pass
    query = current_user.followers.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)

    return render_template('edit_follower.html',  title=_('Edit follower') + f" - {current_user.username }", users=pagination.items, user=user, pagination=pagination)


@bp.route('/edit-following', methods=['GET', 'POST'])
@login_required
def edit_following():
    if request.method == 'POST':
        pass
    query = current_user.following.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)

    return render_template('edit_following.html',  title=_('Edit follower') + f" - {current_user.username }", users=pagination.items, user=user, pagination=pagination)


@bp.route('/notification')
@login_required
def notification():
    since = int(request.args.get('since', 0.0, type=float))
    notifications = current_user.query_notification_since(since)

    try:
        return [{
            'name': n.name,
            'data': n.get_payload()['count'],
            'timestamp': n.timestamp.timestamp()
        } for n in notifications]
    except:
        return {}


@bp.route('/view-notification', methods=['GET', 'POST'])
@login_required
def view_notification():
    current_user.last_notification_read_time = datetime.now(timezone.utc)
    db.session.flush()    
    query = current_user.query_notification()
    current_user.put_notification_count()

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    db.session.commit()

    return render_template('view_notification.html', title=_('View notification') + f" - {current_user.username}", notifications=pagination.items, pagination=pagination)


@bp.route('/del-notification/<int:id>', methods=['POST'])
@login_required
def del_notification(id):
    query = current_user.query_old_notification()

    db.session.execute(current_user.notifications.delete().where(Notification.id == id))

    for q in query:
        q.del_self()

    db.session.flush()
    current_user.put_notification_count()
    db.session.commit()
    return {
        "notification_count": current_user.notification_count(),
    }


@bp.route('/edit-account', methods=['GET', 'POST'])
@login_required
def edit_account():
    if request.method == 'POST':
        if request.form.get('submit') == 'edit_account':
            bucket = 'profile-pics'
            current_user.phone = request.form.get('phone')
            current_user.location = request.form.get('location')
            current_user.banner_flag = request.form.get('banner_flag')
            current_user.contact_email = request.form.get('contact_email')
            current_user.about_me = request.form.get('about_me')
            current_user.language = g.lang
            current_user.utc_offset = request.form.get('utc_offset')
            current_user.viewer = int(request.form.get('viewer'))
            current_user.song = json.dumps({'name':request.form.get('song_name'), 'link': request.form.get('song_link')}) if request.form.get('song_name') and request.form.get('song_link') else None
            current_user.birth = datetime.strptime(request.form.get('birth'), '%Y-%m-%d') if request.form.get('birth') else None

            if request.form.get('photo_link') and not request.form.get('del_photo'):
                current_user.del_photo()
                current_user.photo = request.form.get('photo_link')

            if request.form.get('del_photo'):
                current_user.del_photo()

            if request.files['photo'].filename != '':
                f = request.files['photo']
                if f.filename != '' and Photo.allowed_file(f.filename):
                    current_user.del_photo()
                    f.filename = secure_filename(f.filename)
                    name = f"{datetime.now(timezone.utc).strftime('%H%M%S-%f-')}{f.filename}"
                    Photo.upload_object(bucket, name, f, 'public-read')
                    current_user.photo = f"{Config.SPACES_URL}/{bucket}/{name}"

            db.session.commit()
            return redirect(url_for('main.user', username=current_user.username))

        db.session.commit()
        return redirect(url_for('main.user', username=current_user.username))

    return render_template('edit_account.html', title=_('Edit account') + f" - {current_user.username}", user=current_user)


@bp.route('/edit-account-admin/<username>', methods=['GET', 'POST'])
@login_required
@permission_required('MODERATE')
def edit_account_admin(username):
    user = User.query_user(username)
    if request.method == 'POST':
        if request.form.get('submit') == 'edit_account':
            user.about_me = request.form.get('about_me')
            user.confirmed = bool(request.form.get('confirmed', False))
            user.verified = bool(request.form.get('verified', False))
            user.label = request.form.get('label')
            user.song = json.dumps({'name':request.form.get('song_name'), 'link': request.form.get('song_link')}) if request.form.get('song_name') and request.form.get('song_link') else None
            user.location = request.form.get('location', None)

            utc_offset = request.form.get('utc_offset')
            utc_time = datetime.now(timezone.utc).strftime('%Y%m%d-%H:%M')            
            user.editor = f"{current_user.username}_{utc_time}_utc_{utc_offset}"            

            if request.form.get('del_photo'):
                user.del_photo()

# Admin cannot set a permission above their own
            if current_user.can('ADMIN'):
                user.disabled = bool(request.form.get('disabled', False))
                if int(request.form.get('permission')) <= current_user.permission:
                    user.set_permission(AccountPermission(int(request.form.get('permission'))).name)

        db.session.commit()
        return redirect(url_for('main.user', username=user.username))

    return render_template('edit_account_admin.html', title=_('Edit account admin') + f" - {user.username}", user=user)


@bp.route('/del-account/<username>', methods=['POST'])
@login_required
def del_account(username):
    user = User.query_user(username)
    if user is None or current_user.id != user.id and not current_user.can('ADMIN'):
        return redirect(url_for('main.index'))
    elif user.check_password(request.form.get('password', '')) or current_user.check_totp(int(request.form.get('mfa_token', 0))):
        user.del_self()
        db.session.commit()
        return redirect(url_for('main.index'))
    else:
        flash(_('Invalid'))
        return redirect(request.referrer)


@bp.route('/inbox')
@login_required
def inbox():
    convo = Conversation.query_mailbox_id()

# Create id list to query
    id_list = []
    for m in convo:
        id_list.append(m)

    query = sa.select(Message).where(Message.id.in_(id_list)).order_by(Message.id.desc())

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    current_user.put_message_count()
    db.session.commit()
    return render_template('inbox.html', title=_('Inbox') + f" - {current_user.username}", messages=pagination.items, pagination=pagination)


@bp.route('/message/<username>')
@login_required
@permission_required('MESSAGE')
def message(username):
    user = User.query_user(username)

    current_user.last_message_read_time = datetime.now(timezone.utc)
    db.session.flush()

# query mailbox and message_id. message_id used in convo loop.
    id_list = list(Conversation.query_message_id(current_user.id, user.id))
    Message.mark_read(id_list)
    db.session.flush()

    current_user.put_message_count()
    messages = Message.query_message_list(id_list)

    db.session.commit()
    return render_template('message.html', title=_('Message'), messages=messages, sender=user)


@bp.route('/send-message/<username>', methods=['POST'])
@login_required
@permission_required('MESSAGE')
def send_message(username):
    user = User.query_user(username)

    utc_offset = request.form.get('utc_offset')
    msg = Message(sender=current_user, recipient=user, body=Message.encrypt(request.form.get('body')), language=g.lang, utc_offset=utc_offset)
    db.session.add(msg)
    db.session.flush()
    if request.files['photo'].filename:
        f = request.files['photo']
        bucket = 'message-pics'
        if f.filename != '' and Photo.allowed_file(f.filename):
            f.filename = secure_filename(f.filename)
            name = f"{uuid.uuid4()}"
            Photo.upload_object(bucket, name, f, 'private')
            photo = json.dumps({"link": f"{Config.SPACES_URL}/{bucket}/{name}"})
            msg.photos = Message.encrypt(photo)

    convo = Conversation.query_convo(current_user.id, user.id)

    if convo:
# Create entry with existing conversation mailbox number
        new_convo = Conversation(mailbox=convo, message_id=msg.id, sender_id=current_user.id, recipient_id=user.id)
        db.session.add(new_convo)
    else:
        mailbox_id = db.session.execute(sa.func.max(Conversation.mailbox)).scalar()        
        mailbox_id = mailbox_id + 1 if mailbox_id else 1
        new_convo = Conversation(mailbox=mailbox_id, message_id=msg.id, sender_id=current_user.id, recipient_id=user.id)
        db.session.add(new_convo)

    utc_offset = request.form.get('utc_offset')
    user.put_message_count()

    db.session.flush()
    message = user.last_message_received()

    db.session.commit()
    return {
        "body": message.decrypt(message.body),
        "timestamp": message.timestamp,
        "photo": Photo.get_url(message.get_photos()['link'].removeprefix(f"{Config.SPACES_URL}/message-pics/")) if message.get_photos() else None
    }


@bp.route('/edit-message')
@login_required
@permission_required('MESSAGE')
def edit_message():
    query = current_user.messages_sent.select().order_by(Message.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    
    return render_template('edit_message.html', title=_('Edit Message'), messages=pagination.items, pagination=pagination)


@bp.route('/del-message/<int:id>', methods=['POST'])
@login_required
def del_message(id):
    message = Message.query_message(id)
    if current_user != message.sender:
        return redirect(request.referrer)
# delete from conversation table
    convo = db.first_or_404(sa.select(Conversation).where(Conversation.message_id == request.form.get('input_id')))

    message.del_message()
    convo.del_conversation()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/invite-chat', methods=['POST'])
@login_required
def invite_chat():
    user = User.query_user(request.form.get('body'), True)

    if user:
        payload = {"title": f"Chatii", "body": f"{request.form.get('roomCode')}", "sender":f"{current_user.username}"}
        utc_offset = request.form.get('utc_offset')        
        user.add_notification(name='invite_chat', payload=payload, item_id=0, item_type='chatii', utc_offset=utc_offset)
        db.session.flush()
        user.put_notification_count()
    else:
        time = datetime.now(timezone.utc).timestamp() * 1000
        data = {'name':'~', 'body': _('%(username)s not found', username=request.form.get('body')), 'time':time}
        socketio.emit('message', data, room=session.get('room'))

    db.session.commit()
    return {}


@bp.route('/chatii', methods=['GET', 'POST'])
@login_required
def chatii():
    if request.args.get('room'):
        session['name'] = current_user.username    
        session['room'] = request.args.get('room')
        return redirect(url_for('main.chatii_room'))

    if request.method == 'POST':
        name = request.form.get('name') if request.form.get('name') == current_user.username else f"~{request.form.get('name')}~"
        code = request.form.get('code').upper()
        join = request.form.get('join', False)
        create = request.form.get('create', False)
              
        if not name:
            return render_template('chatii.html', title=_('Chatii'), err_msg=_('Enter name'), code=code, name=name)
            
        if join != False and not code:
            return render_template('chatii.html', title=_('Chatii'), err_msg=_('Enter code'), code=code, name=name)
            
        room = code
        if create != False:
            room = Chatii.generate_room_code(6)
            Chatii.rooms[room] = {"members": 0, "messages": [], "time": None}
        elif code not in Chatii.rooms:
            return render_template('chatii.html', err_msg=_('Not found'), code=code, name=name)
            
        session['name'] = name
        session['room'] = room
        return redirect(url_for('main.chatii_room'))
        
    return render_template('chatii.html', title=_('Chatii'))


@bp.route('/chatii-room', methods=['GET', 'POST'])
@login_required
def chatii_room():
    name = session.get('name')
    room = session.get('room')
    if room is None or name is None or room not in Chatii.rooms:
        return redirect(url_for('main.chatii'))
    
    messages = Chatii.rooms[room]['messages'][-5:]
    
    return render_template('chatii_room.html', title=_('Chat Room'), code=room, messages=messages)


@socketio.on('message')
def socket_message(data):
# Receive message and send to room
    room = session.get('room')
    if room not in Chatii.rooms:
        return

# Timestamp in milliseconds since Unix epoch
    time = datetime.now(timezone.utc).timestamp() * 1000
    content = {
        "name": session.get("name"),
        "body": data["body"],
        "img": data["img"],
        "time": time
    }

    send(content, to=room)
    Chatii.rooms[room]["messages"][-5:]
    Chatii.rooms[room]["messages"].append(content)


@socketio.on('connect')
def socket_connect(auth):
    room = session.get('room')
    name = session.get('name')
    if not room or not name:
        return
        
    if room not in Chatii.rooms:
        leave_room(room)
        return
        
    join_room(room)
    time = datetime.now(timezone.utc).timestamp() * 1000
    send({"name": name, "body": "&#x1F6B6;&#xfe0e;", "time":time}, to=room)
    Chatii.rooms[room]["members"] += 1


@socketio.on('disconnect')
def socket_disconnect():
    room = session.get('room')
    name = session.get('name')
    leave_room(room)

    if room in Chatii.rooms:
        Chatii.rooms[room]["members"] -= 1
        if Chatii.rooms[room]["members"] < 1:
            del Chatii.rooms[room]

    time = datetime.now(timezone.utc).timestamp() * 1000
    send({"name": name, "body": "&#x1F6B7;&#xfe0e;", "time":time}, to=room)


@bp.route('/about')
def about():
    return render_template('about.html', title=_('About'))


@bp.route('/contact')
def contact():
    return render_template('contact.html', title=_('Contact'))


@bp.route('/promote')
def promote():
    return render_template('promote.html', title=_('Promote'))


@bp.route('/humans.txt')
def humans_txt():
    return render_template('humans.txt', title=_('Humans.txt'))


@bp.route('/robots.txt')
def robots_txt():
    return render_template('robots.txt', title=_('Robots.txt'))


# check if user has an exporting task in progress to prevent a user from running two export tasks
# launch_task() first arg is name of function that is passed to RQ worker, prefixed with app.tasks. 2nd arg is description showned to user. Both values written to Task object in DB.
#@bp.route('/export_posts')
#@login_required
#def export_posts():
#    if current_user.get_task_in_progress('export_posts'):
#        flash(_('Export in progress'))
#    else:
#        current_user.launch_task('export_posts', _('Exporting posts...'))
#    try:
#        db.session.commit()
#    except Exception as e:
#        flash(_('DB Commit Fail - export_posts()'))
#    return redirect(url_for('main.user', username=current_user.username))
