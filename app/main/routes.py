from app import db, socketio
from app.decorators import permission_required
from app.main import bp
from app.models import User, Post, Comment, Conversation, Message, Notification, Tag, Vote, AccountPermission, Photo, Flag, FlagReason, Chatii
from datetime import datetime, timezone, timedelta
from flask import abort, render_template, flash, redirect, request, url_for, g, current_app, request, make_response, session, json
from flask_login import current_user, login_required
from flask_babel import _, get_locale
from flask_wtf import CSRFProtect
from flask_socketio import emit, join_room, leave_room, send
from random import SystemRandom
from time import time
from werkzeug.utils import secure_filename
import sqlalchemy as sa
import os
import uuid


@bp.before_app_request
def before_app_request():
# g object is designed to store data that needs to be available throughout the request context
    g.locale = str(get_locale())


@bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)

        db.session.commit()

    if request.method == 'POST':
# >>>type(request.accept_languages)... <class 'werkzeug.datastructures.accept.LanguageAccept'>
        g.language = str(request.accept_languages).split(',')[0] if request.accept_languages != '*' else 'en-US'


#print(json.dumps(dict(request.form)))
@bp.route('/')
@bp.route('/home')
@bp.route('/index')
def index():
    query = sa.select(Post).order_by(Post.votes.desc(), Post.comments.desc(), Post.timestamp.desc()).limit(200)
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    for post in pagination.items:
        if not post.can_view():
            pagination.items.remove(post)

    return render_template('index.html', title=_('Index'), posts=pagination.items, pagination=pagination)


@bp.route('/feed')
@login_required
def feed():
    current_user.last_feed_read_time = datetime.now(timezone.utc)
    query = current_user.following_posts().where(Post.author != current_user).order_by(Post.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    
    db.session.commit()
    return render_template('feed.html', title=_('Feed') + f" - {current_user.username}", posts=pagination.items, pagination=pagination)


@bp.route('/new-post', methods=['GET', 'POST'])
@login_required
@permission_required('WRITE')
def new_post():
    if request.method == 'POST':
        nsfw = True if request.form.get('nsfw') else False
        disable_comments = True if request.form.get('disable_comments') else False
        utc_offset = request.form.get('utc_offset')
        post = Post(title=request.form.get('title'), body=request.form.get('body'), author=current_user, disable_comments=disable_comments, nsfw=nsfw, language=g.language, utc_offset=utc_offset)
        db.session.add(post)
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

# max uploads is 5. Cannot upload photo files if 5 links are added
# If the user does not select a file, the browser submits an empty file without a filename.
# Empty files will return [<FileStorage: '' ('application/octet-stream')>]
        if request.files['photo'].filename != '' and p_count < 5:
            photo_files = request.files.getlist('photo')[0:5]
            bucket = 'post-pics'
            for f in photo_files:
                if f.filename != '' and Photo.allowed_file(f.filename):
# sanitize filename before setting name
                    f.filename = secure_filename(f.filename)    
                    name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}-{current_user.username}-{f.filename}"
                    if Photo.upload_object(bucket, name, f, 'public-read'):
                        photo_name.append(f.filename)
                        photo_link.append(f"{Photo.SPACES_URL}/{bucket}/{name}")
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})

        if request.form.get('tags'):
            form_tags = request.form.get('tags').split()[0:5]
# check for duplicate tags
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
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if not post.can_view():
        return redirect(url_for('main.user', username=post.author.username))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments_count() - 1) // current_app.config['COMMENTS_PER_PAGE'] + 1
    query = post.get_comments()
    pagination = db.paginate(query, page=page, per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    if current_user != post.author:
        for c in pagination.items:
            pagination.items.remove(c) if c.direct else None

    return render_template('post.html', title= f"{post.title} - {post.author.username}", post=post, comments=pagination.items, pagination=pagination)


@bp.route('/comment/<int:id>', methods=['POST'])
@login_required
@permission_required('COMMENT')
def comment(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if post.locked:
        return redirect(request.referrer)
    if not post.disable_comments:
        if request.form.get('pin_comment') and post.pin_comments < 2 and (current_user == post.author or current_user.can('MODERATE')):
            pin_comments = post.pin_comments + 1
            pinned = True               
        else:
            pin_comments = post.pin_comments
            pinned = False

        direct = True if request.form.get('direct_comment') else False
        ghost = True if request.form.get('ghost_comment') else False
        utc_offset = request.form.get('utc_offset')
        comment = Comment(author=current_user._get_current_object(), body=request.form.get('body'), post_id=id, user_id=current_user.id, pinned=pinned, direct=direct, ghost=ghost, language=g.language, utc_offset=utc_offset)
        post.pin_comments = pin_comments

        db.session.add(comment)
        db.session.flush()
        if request.form.get('direct_comment'):
            post.direct_comments_count()
        post.comments_count()

        notice = db.session.execute(post.author.notifications.select().where((Notification.item_id == id) & (Notification.name == 'new_comment'))).scalar()
        if notice:
# comment = db.session.execute(sa.select(Comment, sa.func.max(Comment.id))).scalar()
            payload = {"key": f"{post.title} \n{comment.body_html if comment.body_html else request.form.get('body')} \n{current_user.username}"}
            notice.update_payload(payload)
            notice.timestamp = datetime.now(timezone.utc)
        else:
            payload = {"key": f"{post.title} \n{request.form.get('body')} \n{current_user.username}"}
            post.author.add_notification(name='new_comment', payload=payload, item_id=id, item_type='comment')

        db.session.commit()
        
    return redirect(request.referrer)


@bp.route('/reply-comment/<int:id>', methods=['POST'])
@login_required
@permission_required('COMMENT')
def reply_comment(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if post.locked:
        return redirect(request.referrer)
    if not post.disable_comments:
        comment = db.session.execute(sa.select(Comment).where(Comment.id == request.form.get('comment_id'))).scalar()
        c_author = db.session.execute(sa.select(User).where(User.id == request.form.get('authorId'))).scalar()
        if comment:
            utc_offset = request.form.get('utc_offset')
            reply = Comment(author=current_user._get_current_object(), body=request.form.get('body'), post_id=id, user_id=current_user.id, parent_id=comment.id, language=g.language, utc_offset=utc_offset)

            db.session.add(reply)
            db.session.flush()
            post.comments_count()

            payload = {"key": f"{post.title} \n{request.form.get('body')} \n{current_user.username}"}
            c_author.add_notification(name='reply_comment', payload=payload, item_id=id, item_type='comment')

            db.session.commit()

    return redirect(request.referrer)


@bp.route('/vote-post/<int:id>', methods=['POST'])
@login_required
@permission_required('WRITE')
def vote_post(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    vote = db.session.execute(sa.select(Vote).where((Vote.user_id == current_user.id) & (Vote.post_id == id))).scalar()

    if post.locked:
        return {
        "count": f"&#x21E7; {post.votes}",
        }
    if vote is None:
        utc_offset = request.form.get('utc_offset')
        vote = Vote(user_id=current_user.id, post_id=id, utc_offset=utc_offset)
        db.session.add(vote)
        db.session.flush()
        count = post.vote_count()
    else:
        db.session.delete(vote)
        db.session.flush()
        count = post.vote_count()

    db.session.commit()
    return {
        "count": f"&#x21E7; {count}",
    }


@bp.route('/vote-comment/<int:id>', methods=['POST'])
@login_required
@permission_required('WRITE')
def vote_comment(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    vote = db.session.execute(sa.select(Vote).where((Vote.user_id == current_user.id) & \
    (Vote.post_id == id) & (Vote.comment_id == request.form.get('input_id')))).scalar()
    comment = db.session.execute(sa.select(Comment).where(Comment.id == request.form.get('input_id'))).scalar()

    if post.locked:
        return {
            "count": f"&#x21E7; {comment.votes}",
        }
    if vote is None:
        utc_offset = request.form.get('utc_offset')
        vote = Vote(user_id=current_user.id, post_id=id, comment_id=comment.id, utc_offset=utc_offset)
        db.session.add(vote)
        db.session.flush()
        count = comment.vote_count()
    else:
        db.session.delete(vote)
        db.session.flush()
        count = comment.vote_count()

    db.session.commit()
    return {
        "count": f"&#x21E7; {count}",
    }


@bp.route('/flag/<int:id>', methods=['POST'])
@login_required
def flag(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    flag = db.session.execute(sa.select(Flag).where((Flag.user_id == current_user.id) & (Flag.post_id == id))).scalar()
    if post.locked:
        return {
            "count": f"&#x1F6A9; {post.flags}",
        }
    if not flag:
        utc_offset = request.form.get('utc_offset')
        flag = Flag(reason=FlagReason[request.form.get('flag')].value, user_id=current_user.id, post_id=id, utc_offset=utc_offset)
        db.session.add(flag)
        db.session.flush()
        count = post.flags_count()
    else:
        db.session.delete(flag)
        db.session.flush()
        count = post.flags_count()

    db.session.commit()
    return {
        "count": f"&#x1F6A9; {count}",
    }


@bp.route('/edit-post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if current_user != post.author and not current_user.can("MODERATE"):
        return redirect(request.referrer)

    if request.method == 'POST':
        post.body = request.form.get('body') if request.form.get('body') else post.body
        post.edit_timestamp = datetime.now(timezone.utc)
        post.disable_comments = True if request.form.get('disable_comments') else False
        post.language = g.language
        utc_offset = request.form.get('utc_offset')
        utc_time = datetime.now(timezone.utc).strftime('%Y%m%d-%H:%M')
        post.editor = f"{current_user.username}_{utc_time}_{utc_offset}"
        nsfw = True if request.form.get('nsfw') else False
        post.nsfw = nsfw
        post.viewer = int(request.form.get('viewer'))
        form_tags = request.form.get('tags').split()[0:5]
        bucket = 'post-pics'
        p_photos = post.get_photos()

        if current_user.can("MODERATE"):
            post.locked = True if request.form.get('lock_post') else False
            post.label = request.form.get('label') if request.form.get('label') and request.form.get('label') != 'null' else None

        if not form_tags:
            post.del_all_tags()

        if form_tags and post.tags:
            post_tags = post.get_tags()

# loop body needs to reference tag.id since there will be duplicate tag.name. Only tags mapped to this post need to be deleted
            for tag in post.tags:
                if tag.name not in form_tags:
                    post.del_tag(tag.id)

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

        photo_name = []
        photo_link = []
# p_max gets the count so photo_name = photo<number>. max uploads is 5
        p_max = 5 - len(p_photos['link']) if p_photos and p_photos['link'] else 5

        if p_photos and p_max > 0 and request.form.getlist('add_photos'):
            i = len(p_photos['link']) if p_photos else 0
            print(i)
            for p in request.form.getlist('add_photos'):
                p_photos['link'].append(f"photo{i + 1}")
                p_photos['link'].append(p)
                print(p_photos['link'])
                print(p_photos['name'])
                i += 1
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})
        elif request.form.getlist('add_photos'):
            for i, l in enumerate(photo_link, start=1):
                photo_name.append(f"photo{i}")
                photo_link.append(l)
                print(photo_name)
                print(photo_link)
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})

        if request.form.getlist('del_photos'):
            for i in range(len(request.form.getlist('del_photos')) - 1, -1, -1):
                p = p_photos['link'][i]
                if "niitii-spaces" in p:
                    Photo.del_object('post-pics', p.removeprefix(f"{Photo.SPACES_URL}/post-pics/"))

                del p_photos['name'][i]
                del p_photos['link'][i]

            photo_name = p_photos['name']
            photo_link = p_photos['link']
            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})

        if request.files['photo'].filename != '':
            photo_files = request.files.getlist('photo')[0:p_max]
            for f in photo_files:
                if f.filename != '' and Photo.allowed_file(f.filename):
                    f.filename = secure_filename(f.filename)
                    name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}-{current_user.username}-{f.filename}"
                    if Photo.upload_object(bucket, name, f, 'public-read'):
                        photo_name.append(f.filename)
                        photo_link.append(f"{Photo.SPACES_URL}/{bucket}/{name}")

            post.photos = json.dumps({"name": photo_name, "link": photo_link, "nsfw": nsfw})

        db.session.commit()
        return redirect(url_for('main.post', id=post.id))

    post_tags = " ".join(post.get_tags())

    return render_template('edit_post.html', title=_('Edit Post') + f" - {post.author.username }", post=post, tags=post_tags)


@bp.route('/del-post/<int:id>', methods=['POST'])
@login_required
def del_post(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))

    if post.user_id == current_user.id or current_user.can("MODERATE"):
        if post.tags:
            for tag in post.tags:
# remove tag from post.tags list
                post.tags.remove(tag)
                db.session.execute(sa.delete(Tag).where(Tag.id == tag.id))

# PRAGMA enables cascade in sqlite
# db.session.execute(sa.text('PRAGMA foreign_keys = ON'))
        post.del_all_votes()
        post.del_all_flags()
        post.del_all_comments()
        post.del_all_photos()
        post.del_all_tags()
        db.session.delete(post)

        db.session.commit()
        return redirect(url_for('main.index'))


@bp.route('/post-comment/<int:id>')
@login_required
def post_comment(id):
    post = db.session.execute(sa.select(Post).where(Post.id == id)).scalar()
    if current_user != post.author and not current_user.can('MODERATE'):
        return redirect(url_for('main.post', id=id))

    query = post.get_comments()
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    if current_user != post.author:
        for c in pagination.items:
            pagination.items.remove(c) if c.direct else None

    return render_template('post_comment.html', title=_('Post Comment') + f" - {post.author.username }", post=post, comments=pagination.items, pagination=pagination)


@bp.route('/user-comment/<username>')
@login_required
def user_comment(username):
    if current_user.username != username and not current_user.can("MODERATE"):
        return redirect(url_for('main.index'))

    user = db.first_or_404(sa.select(User).where(User.username == username))
    query = user.comments.select().where(Comment.user_id == user.id).order_by(Comment.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('user_comment.html', title=_('User Comment') + f" - {user.username }", comments=pagination.items, user=user, pagination=pagination)


@bp.route('/disable-comment/<int:id>', methods=['POST'])
@login_required
def disable_comment(id):
    comment = db.first_or_404(sa.select(Comment).where(Comment.id == id))
    post = db.first_or_404(sa.select(Post).where(Post.id == comment.post_id))

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
    comment = db.first_or_404(sa.select(Comment).where(Comment.id == id))
    post = db.first_or_404(sa.select(Post).where(Post.id == comment.post_id))

    if current_user != comment.author and current_user != post.author and not current_user.can("MODERATE"):
        return redirect(request.referrer)

    if (current_user == post.author or current_user.can('MODERATE')):
        if comment.pinned:
            post.pin_comments -= 1

        post.removed_comments += 1

    db.session.delete(comment)
    db.session.flush()
    post.comments_count()

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/tag/<name>')
def view_tag(name):
    tag = db.first_or_404(sa.select(Tag).where(Tag.name == name))
    query = Post.tag_query(name)

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    return render_template('tag.html', title=_('Tag'), posts=pagination.items, pagination=pagination)


@bp.route('/<username>')
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    query = user.posts.select().order_by(Post.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    age = (datetime.now() - user.birth).days // 365 if user.birth else None
    
    for post in pagination.items:
        if not post.can_view():
            pagination.items.remove(post)

    return render_template('user.html',  title=_('User') + f" - {user.username }", user=user, posts=pagination.items, pagination=pagination, age=age)


@bp.route('/ping/<int:id>', methods=['POST'])
@login_required
def ping(id):
    user = db.first_or_404(sa.select(User).where(User.id == id))
    sender = f"\n{current_user.username}" if request.form.get('pingCheck') else '\n...'
    payload = {"key": f"Ping \n{request.form.get('body')} {sender}"}
    user.add_notification(name='new_ping', payload=payload, item_id=0, item_type='ping')

    db.session.flush()
    ping_count = db.session.execute(user.notifications.select().where(Notification.name == 'ping_count')).scalar()

    if ping_count:
        ping_count.update_payload({"key": f"{user.ping_count()}"})
    else:
        payload = {"key": f"{user.ping_count()}"}
        user.add_notification(name='ping_count', payload=payload, item_id=0, item_type='count')

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/follow/<int:id>', methods=['POST'])
@login_required
def follow(id):
    user = db.first_or_404(sa.select(User).where(User.id == id))
# Cannot follow yourself
    if user is None or user == current_user:
        return redirect(request.referrer)
    current_user.follow(user)

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/unfollow/<int:id>', methods=['POST'])
@login_required
def unfollow(id):
    user = db.first_or_404(sa.select(User).where(User.id == id))
# Cannot unfollow yourself
    if user is None or user == current_user:
        return redirect(request.referrer)
    current_user.unfollow(user)

    db.session.commit()
    return redirect(request.referrer)


@bp.route('/follower/<username>')
def follower(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    query = user.followers.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)
            
    return render_template('follower.html',  title=_('Follower') + f" - {user.username }", users=pagination.items, user=user, pagination=pagination)
    

@bp.route('/following/<username>')
def following(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    query = user.following.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)
        
    return render_template('following.html',  title=_('Following') + f" - {user.username }", users=pagination.items, user=user, pagination=pagination)


@bp.route('/edit-account/<username>', methods=['GET', 'POST'])
@login_required
def edit_account(username):
    if request.method == 'POST' and current_user.username == username:
        if request.form.get('submit') == 'edit_account':
            bucket = 'profile-pics'
            current_user.phone = request.form.get('phone')
            current_user.location = request.form.get('location')
            current_user.banner_flag = request.form.get('banner_flag')
            current_user.contact_email = request.form.get('contact_email')
            current_user.about_me = request.form.get('about_me')
            current_user.language = g.language
            current_user.utc_offset = request.form.get('utc_offset')
            current_user.viewer = int(request.form.get('viewer'))
            current_user.song = json.dumps({'name':request.form.get('song_name'), 'link': request.form.get('song_link')}) if request.form.get('song_name') and request.form.get('song_link') else None
            current_user.birth = datetime.strptime(request.form.get('birth'), '%Y-%m-%d') if request.form.get('birth') else None

            if request.form.get('photo_link'):
                if current_user.photo:
                    current_user.del_photo()
                    current_user.photo = request.form.get('photo_link') if not request.form.get('del_photo') else None
                else:
                    current_user.photo = request.form.get('photo_link') if not request.form.get('del_photo') else None

            if request.files['photo'].filename != '':
                f = request.files['photo']
                if f.filename != '' and Photo.allowed_file(f.filename):
                    if current_user.photo:
                        current_user.del_photo()

                    f.filename = secure_filename(f.filename)
                    name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}-{current_user.username}-{f.filename}"
                    if Photo.upload_object(bucket, name, f, 'public-read'):
                        current_user.photo = f"{Photo.SPACES_URL}/{bucket}/{name}"

            db.session.commit()
            return redirect(url_for('main.user', username=current_user.username))

        db.session.commit()
        return redirect(url_for('main.user', username=current_user.username))

    return render_template('edit_account.html', title=_('Edit account') + f" - {current_user.username}", user=current_user)


@bp.route('/edit-account-admin/<username>', methods=['GET', 'POST'])
@login_required
@permission_required('MODERATE')
def edit_account_admin(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    if request.method == 'POST':
        if request.form.get('submit') == 'edit_account':
            user.about_me = request.form.get('about_me')
            user.photo = request.form.get('photo_link') if not request.form.get('del_photo') else None
            user.confirmed = True if request.form.get('confirmed') else False
            user.verified = True if request.form.get('verified') else False
            user.label = request.form.get('label')
            user.song = json.dumps({'name':request.form.get('song_name'), 'link': request.form.get('song_link')}) if request.form.get('song_name') and request.form.get('song_link') else None
            user.location = request.form.get('location') if request.form.get('location') else None

            utc_offset = request.form.get('utc_offset')
            utc_time = datetime.now(timezone.utc).strftime('%Y%m%d-%H:%M')            
            user.editor = f"{current_user.username}_{utc_time}_{utc_offset}"

# Admin cannot set a permission above their own
            if current_user.can('ADMIN'):
                user.disabled = request.form.get('disabled') if request.form.get('disabled') else False
                if int(request.form.get('permission')) <= current_user.permission:
                    user.set_permission(AccountPermission(int(request.form.get('permission'))).name)

        db.session.commit()
        return redirect(url_for('main.user', username=user.username))

    return render_template('edit_account_admin.html', title=_('Edit account admin') + f" - {user.username}", user=user)


@bp.route('/del-account/<int:id>', methods=['POST'])
@login_required
def del_account(id):
    user = db.first_or_404(sa.select(User).where(User.id == id))
    if user is None or current_user.id != user.id and not current_user.can('ADMIN'):
        return redirect(url_for('main.index'))
    elif user.check_password(request.form.get('password')) or current_user.check_password(request.form.get('password')):
        if user.photo:
            user.del_photo()
# Delete post photos from storage Spaces
        posts = db.session.execute(user.posts.select()).scalars()
        for p in posts:
            p.del_all_comments()
            p.del_all_flags()
            p.del_all_votes()
            p.del_all_tags()
            p.del_all_photos()

        messages = db.session.execute(user.messages_sent.select()).scalars()

        for m in messages:
            if m.get_photos():
                m.del_all_photos()

# PRAGMA enables cascade in sqlite
        db.session.execute(sa.text('PRAGMA foreign_keys = ON'))
        user.del_all_sent_messages()
        user.del_all_comments()
        user.del_all_votes()
        user.del_all_flags()
        user.del_all_notifications()
        user.del_all_posts()
        user.del_all_follows()
        user.del_user()

        db.session.commit()
        return redirect(url_for('main.index'))

    else:
        flash(_('Invalid'))
        return redirect(request.referrer)


@bp.route('/inbox')
@login_required
@permission_required('MESSAGE')
def inbox():
    current_user.last_message_read_time = datetime.now(timezone.utc)
    payload = {"key": "0"}
# new_message_count notification is created in message() route
    current_user.update_notification(name="new_message_count", payload=payload)

    db.session.flush()

# query mailbox ids
    convo = db.session.execute(sa.select(sa.func.max(Conversation.message_id)).where((Conversation.sender_id == current_user.id) | (Conversation.recipient_id == current_user.id)).group_by(Conversation.mailbox)).scalars()

# Create id list to query
    id_list = []
    for m in convo:
        id_list.append(m)

    query = sa.select(Message).where(Message.id.in_(id_list)).order_by(Message.id.desc())

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    db.session.commit()

    return render_template('inbox.html', title=_('Inbox') + f" - {current_user.username}", messages=pagination.items, pagination=pagination)


@bp.route('/message/<username>')
@login_required
@permission_required('MESSAGE')
def message(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))

    current_user.last_message_read_time = datetime.now(timezone.utc)
    db.session.flush()

# query mailbox and message_id. message_id used in convo loop.
    convo = db.session.execute(sa.select(Conversation.mailbox, Conversation.message_id).where(((Conversation.sender_id == current_user.id) & (Conversation.recipient_id == user.id)) | ((Conversation.sender_id == user.id) & (Conversation.recipient_id == current_user.id))))

# Create message ids to query    
    id_list = []
    for m in convo:
        id_list.append(m.message_id)
    
    query = sa.select(Message).where(Message.id.in_(id_list)).order_by(Message.id.asc())
    messages = db.session.execute(query).scalars()
    db.session.commit()

    return render_template('message.html', title=_('Message'), messages=messages, sender=user)


@bp.route('/send-message/<username>', methods=['POST'])
@login_required
def send_message(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))

    utc_offset = request.form.get('utc_offset')
    msg = Message(sender=current_user, recipient=user, body=Message.encrypt(request.form.get('body')), language=g.language, utc_offset=utc_offset)
    db.session.add(msg)
    db.session.flush()
    if request.files['photo'].filename:
        f = request.files['photo']
        bucket = 'message-pics'
        if Photo.allowed_file(f.filename):
            f.filename = secure_filename(f.filename)
            name = f"{uuid.uuid4()}"
            if Photo.upload_object(bucket, name, f, 'private'):
                msg.photos = json.dumps({"link": f"{Photo.SPACES_URL}/{bucket}/{name}"})

    convo = db.session.execute(sa.select(Conversation.mailbox).where(((Conversation.sender_id == current_user.id) & (Conversation.recipient_id == user.id)) | ((Conversation.sender_id == user.id) & (Conversation.recipient_id == current_user.id)))).scalar()
    if convo:
# Create entry with existing conversation mailbox number
        new_convo = Conversation(mailbox=convo, message_id=msg.id, sender_id=current_user.id, recipient_id=user.id)
        db.session.add(new_convo)
    else:
        mailbox_id = db.session.execute(sa.select(Conversation.mailbox, sa.func.max(Conversation.mailbox))).scalar()
# Create a new mailbox with highest mailbox + 1
        mailbox_id += 1
        new_convo = Conversation(mailbox=mailbox_id, message_id=msg.id, sender_id=current_user.id, recipient_id=user.id)
        db.session.add(new_convo)

    notice = db.session.execute(user.notifications.select().where(Notification.name == 'new_message_count')).scalar()
    if notice:
        count = json.loads(notice.payload_json)['key']
        payload = {"key": f"{int(count) + 1}"}
        user.update_notification(name="new_message_count", payload=payload)
    else:
        payload = {"key": "1"}
        user.add_notification(name='new_message_count', payload=payload, item_id=0, item_type='count')

    db.session.flush()
    message = db.session.execute(user.messages_received.select().where(Message.sender == current_user).order_by(Message.id.desc())).scalar()

    db.session.commit()
    return {
        "body": message.decrypt(),
        "timestamp": message.timestamp,
        "photo": Photo.get_url(message.get_photos()['link'].removeprefix(f"{Photo.SPACES_URL}/message-pics/")) if message.get_photos() else None
    }


@bp.route('/edit-message')
@login_required
def edit_message():
    query = current_user.messages_sent.select().order_by(Message.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    
    return render_template('edit_message.html', title=_('Edit Message'), messages=pagination.items, pagination=pagination)


@bp.route('/del-message/<int:id>', methods=['POST'])
@login_required
def del_message(id):
    message = db.session.execute(sa.select(Message).where(Message.id == id)).scalar()
    if current_user != message.sender:
        return redirect(request.referrer)
    if message.photos:
        bucket = 'message-pics'
        name = message.get_photos()['link'].removeprefix(f"{Photo.SPACES_URL}/{bucket}/")
        Photo.del_object(bucket, name)
# delete from conversation table
    convo = db.session.execute(sa.select(Conversation).where(Conversation.message_id == request.form.get('input_id'))).scalar()

    db.session.delete(message)
    db.session.delete(convo)
    db.session.commit()

    return redirect(request.referrer)


@bp.route('/view-notification', methods=['GET', 'POST'])
@login_required
def view_notification():
    current_user.last_notification_read_time = datetime.now(timezone.utc)
    query = current_user.notifications.select().where(Notification.item_type != "count").order_by(Notification.timestamp.desc())

    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    db.session.commit()

    return render_template('view_notification.html', title=_('View notification') + f" - {current_user.username}", notifications=pagination.items, pagination=pagination)


@bp.route('/notification')
@login_required
def notification():
# typecast 'since' to fix error: (psycopg2.errors.UndefinedFunction) operator does not exist: timestamp without time zone > integer
    since = int(request.args.get('since', 0.0, type=float))
    query = current_user.notifications.select().where((Notification.timestamp > datetime.fromtimestamp(since)) & (Notification.name != "ping_count") & (Notification.name != "new_message_count")).order_by(Notification.timestamp.asc())
    notifications = db.session.execute(query).scalars()

    try:
        return [{
            'name': n.name,
            'data': n.get_payload()['key'],
            'timestamp': n.timestamp.timestamp()
        } for n in notifications]
    except:
        return {}


@bp.route('/del-notification/<int:id>', methods=['POST'])
@login_required
def del_notification(id):
    query = db.session.execute(current_user.notifications.select().where(Notification.item_type != "count").order_by(Notification.timestamp.desc())).scalars()
    db.session.execute(current_user.notifications.delete().where(Notification.id == id))
    db.session.flush()
# delete notifications older than 30days
    for q in query:
        if q.timestamp < (datetime.now() - timedelta(days=30)):
            db.session.delete(q)

    db.session.commit()
    return {
        "notification_count": current_user.new_notification_count(),
        "ping_count": current_user.ping_count(),
    }


@bp.route('/search')
def search():
    q = request.args.get('q')
    if q:
        query = sa.select(Post).where(Post.title.icontains(q) | Post.body.icontains(q)).order_by(Post.timestamp.desc()).limit(20)
        pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    else:
        return redirect(request.referrer)

    return render_template('search.html', title=_('Search'), posts=pagination.items, pagination=pagination, q=q)


@bp.route('/invite-chat', methods=['POST'])
@login_required
def invite_chat():
    user = db.session.execute(sa.select(User).where(User.username == request.form.get('body'))).scalar()
    if user and request.form.get('submit') == 'inviteChat':
        payload = {"key": f"Chatii \n{request.form.get('roomCode')} \n{current_user.username}"}
        user.add_notification(name='invite_chat', payload=payload, item_id=0, item_type='chatii')
        db.session.commit()
    return {}


@bp.route('/chatii', methods=['GET', 'POST'])
@login_required
def chatii():
# Room lobby
    if request.method == 'POST':
        name = request.form.get('name') if request.form.get('name') == current_user.username else f"~{request.form.get('name')}~"
# browser will submit in lowercase. Room code must be uppercase.
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
        return redirect(url_for('main.room'))
        
    return render_template('chatii.html', title=_('Chatii'))


@bp.route('/chatii-room', methods=['GET', 'POST'])
@login_required
def room():           
    room = session.get('room')
    if room is None or session.get('name') is None or room not in Chatii.rooms:
        return redirect(url_for('main.chatii'))
    
# Slice list to keep the last 5 messages
    messages = Chatii.rooms[room]['messages'][-5:]
    
    return render_template('chatii_room.html', title=_('Chat Room'), code=room, messages=messages)


@socketio.on('message')
def message(data):
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
def connect(auth):
    room = session.get('room')
    name = session.get('name')
    if not room or not name:
        return
        
    if room not in Chatii.rooms:
        leave_room(room)
        return
        
    join_room(room)
    time = datetime.now(timezone.utc).timestamp() * 1000
    send({"name": name, "body": "&#x1F6B6", "time":time}, to=room)
    Chatii.rooms[room]["members"] += 1


@socketio.on('disconnect')
def disconnect():
    room = session.get('room')
    name = session.get('name')
    leave_room(room)
    
    if room in Chatii.rooms:
        Chatii.rooms[room]["members"] -= 1
        if Chatii.rooms[room]["members"] < 1:
            del Chatii.rooms[room]

    time = datetime.now(timezone.utc).timestamp() * 1000
    send({"name": name, "body": "&#x1F6B7", "time":time}, to=room)


@bp.route('/about')
def about():
    return render_template('about.html', title=_('About'))


@bp.route('/contact')
def contact():
    return render_template('contact.html', title=_('Contact'))


@bp.route('/promote')
def promote():
    return render_template('promote.html', title=_('Promote'))


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
