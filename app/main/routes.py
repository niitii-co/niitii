from app import db, socketio
from app.decorators import permission_required
from app.main import bp
from app.models import User, Post, Comment, follows as follows_tbl, Message, Notification, Tag, tags as tags_tbl, Vote, Permission, Photo, Flag, FlagReason, Chatii
from datetime import datetime, timezone
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
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as e:
            print(e)
    g.locale = str(get_locale())

#print(json.dumps(dict(request.form)))
@bp.route('/', methods=['GET'])
@bp.route('/index', methods=['GET'])
def index():
    query = sa.select(Post).order_by(Post.timestamp.desc())
    posts = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    
    return render_template('index.html', title=_('Index'), posts=posts.items, pagination=posts)


@bp.route('/feed', methods=['GET'])
@login_required
def feed():
    current_user.last_feed_read_time = datetime.now(timezone.utc)
    query = current_user.following_posts().where(Post.author != current_user).order_by(Post.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    
    try:
        db.session.commit()
    except Exception as e:
        flash(_('DB Commit Fail - feed()'))
        print(e)

    return render_template('feed.html', title=_('Feed - ') + f"{current_user.username}", posts=pagination.items, pagination=pagination)


@bp.route('/new-post', methods=['GET', 'POST'])
@login_required
@permission_required('WRITE')
def new_post():
    if request.method == 'POST':
        nsfw = True if request.form.get('post_nsfw') else False
        post = Post(title=request.form.get('title'), body=request.form.get('body'), author=current_user, disable_comments=request.form.get('disable_comments'),\
               nsfw=nsfw, language=request.accept_languages.best_match(current_app.config['LANGUAGES']))
        db.session.add(post)
        photo_name = []
        photo_link = []

        if request.form.get('photo_link'):
            photo_links = request.form.get('photo_link').split()[0:5]        
            nsfw = True if request.form.get('photo_nsfw') else False
            for i, f in enumerate(photo_links):
                photo_name.append(f"photo{i + 1}")
                photo_link.append(f)
            post.photo = {"name": photo_name, "link": photo_link, "nsfw": nsfw}


        photo_files = request.files.getlist('photo')[0:5]
        # Empty files will return list[0] = [<FileStorage: '' ('application/octet-stream')>]
        if photo_files[0].filename != '':
            bucket = 'post-pics'
            nsfw = True if request.form.get('photo_nsfw') else False
            for f in photo_files:
                if f.filename != '' and Photo.allowed_file(f.filename):
                    name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}-{current_user.username}-{current_user.id}-{f.filename}"
                    f.filename = secure_filename(f.filename)
                    if Photo.upload_object(bucket, name, f, 'public-read'):
                        photo_name.append(f.filename)
                        photo_link.append(f"{Photo.SPACES_URL}/{bucket}/{name}")
            post.photo = {"name": photo_name, "link": photo_link, "nsfw": nsfw}


        if request.form.get('tags'):
            tags = request.form.get('tags').split()[0:5]
            for tag in tags:
                db.session.add(Tag(name=tag.replace('#', ''), posts=[post]))

        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - new_post()'))
            print(e)
        return redirect(url_for('main.index'))
    return render_template('new_post.html', title=_('New Post'))


#https://flask-sqlalchemy.palletsprojects.com/en/3.1.x/queries/
@bp.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if request.method == 'POST' and current_user.can("COMMENT"):
        if request.form.get('submit') == 'comment' and not post.disable_comments:
            if request.form.get('pin_comment') and post.pin_comments < 2 and (current_user == post.author or current_user.can('MODERATE')):
                pin_comments = post.pin_comments + 1
                pinned = True               
            else:
                pin_comments = post.pin_comments
                pinned = False
            comment = Comment(body=request.form.get('body'), author=current_user._get_current_object(), post_id=id, user_id=current_user.id, pinned=pinned)
            notice = db.session.execute(post.author.notifications.select().where((Notification.item_id == id) & (Notification.item_type == 'comment'))).scalar()
            post.pin_comments = pin_comments
            db.session.add(comment)
            if notice:
                payload = f"{post.title}" + f"\n" + f"{current_user.username} - {request.form.get('body')}"            
                notice.payload_json = payload
                notice.timestamp = datetime.now(timezone.utc)
            else:
                payload = f"{post.title}" + f"\n" + f"{current_user.username} - {request.form.get('body')}"         
                db.session.add(Notification(user=post.author, name='new_comment', payload_json=payload, item_id=id, item_type='comment'))
                
            try:
                db.session.commit()
                return redirect(request.referrer)                
            except Exception as e:
                flash(_('DB Commit Fail - post()'))
                print(e)
        elif request.form.get('submit') == 'reply_comment' and not post.disable_comments:
            comment = db.session.execute(sa.select(Comment).where(Comment.id == request.form.get('parent_id'))).scalar()
            post = db.session.execute(sa.select(Post).where(Post.id == comment.post_id)).scalar()
            if comment and post and current_user.can("COMMENT"):
                reply_comment = Comment(body=request.form.get('body'), author=current_user._get_current_object(), post_id=id, user_id=current_user.id, parent_id=comment.id)
                notice = db.session.execute(post.author.notifications.select().where((Notification.item_id == id) & (Notification.item_type == 'comment'))).scalar()
                db.session.add(reply_comment)
                if notice:
                    payload = f"{post.title}" + f"\n" + f"{current_user.username} - {request.form.get('body')}"                
                    notice.payload_json = payload
                    notice.timestamp = datetime.now(timezone.utc)                    
                else:
                    payload = f"{post.title}" + f"\n" + f"{current_user.username} - {request.form.get('body')}"
                    db.session.add(Notification(user=post.author, name='new_comment', payload_json=payload, item_id=id, item_type='comment'))
                    
            try:
                db.session.commit()
                return redirect(request.referrer)                
            except Exception as e:
                flash(_('DB Commit Fail - post()'))
                print(e)                    
        elif request.form.get('submit') == 'vote_post' and current_user.can('WRITE'):
            vote = db.session.execute(sa.select(Vote).where((Vote.user_id == current_user.id) & (Vote.post_id == id))).scalar()
            count = post.votes_count()
            if vote is None:
                vote = Vote(user_id=current_user.id, post_id=id, item_type='post')
                count += 1
                db.session.add(vote)
            else:
                count -= 1
                db.session.delete(vote)
            try:
                db.session.commit()
                return {
                    "count": f"&#x21E7; {count}",
                }
            except Exception as e:
                flash(_('DB Commit Fail - post()'))
                print(e)
        elif request.form.get('submit') == 'vote_comment' and current_user.can('WRITE'):
            vote = db.session.execute(sa.select(Vote).where((Vote.user_id == current_user.id) & (Vote.comment_id == request.form.get('input_id')))).scalar()
            comment = db.session.execute(sa.select(Comment).where(Comment.id == request.form.get('input_id'))).scalar()
            count = comment.votes_count()
            if current_user.can("COMMENT") and vote is None:
                vote = Vote(user_id=current_user.id, comment_id=request.form.get('input_id'), item_type='comment')
                count += 1
                db.session.add(vote)
            else:
                count -= 1
                db.session.delete(vote)
            try:
                db.session.commit()
                return {
                    "count": f"&#x21E7; {count}",
                }            
            except Exception as e:
                flash(_('DB Commit Fail - post()'))
                print(e)
        elif request.form.get('flag'):
            flag = db.session.execute(sa.select(Flag).where((Flag.user_id == current_user.id) & (Flag.post_id == id))).scalar()
            count = post.flags_count()            
            if not flag:
                flag = Flag(reason=FlagReason[request.form.get('flag')].value, user_id=current_user.id, post_id=id)
                count += 1
                db.session.add(flag)
            else:
                count -= 1
                db.session.delete(flag)
            try:
                db.session.commit()
                return {
                    "count": f"&#x1F6A9; {count}",
                }           
            except Exception as e:
                flash(_('DB Commit Fail - post()'))
                print(e)
        return redirect(request.referrer)
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments_count() - 1) // current_app.config['COMMENTS_PER_PAGE'] + 1
#    query = sa.select(Comment).where(Comment.post_id == id).order_by(Comment.pinned.desc(), Comment.timestamp)
    query = post.comments()
    pagination = db.paginate(query, page=page, per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('post.html', title=_('Post - ') + f"{post.author.username}", post=post, comments=pagination.items, pagination=pagination)


@bp.route('/edit-post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = db.first_or_404(sa.select(Post).where(Post.id == id))
    if current_user != post.author and not current_user.can("MODERATE"):
        return redirect(request.referrer)
    if request.form.get('submit') == 'edit_post':
        post.body = request.form.get('body')
        post.edit_timestamp = datetime.now(timezone.utc)
        post.disable_comments = True if request.form.get('disable_comments') else False
        post.nsfw = True if request.form.get('post_nsfw') else False
        post.label = request.form.get('label') if request.form.get('label') and request.form.get('label') != 'null' and current_user.can('MODERATE') else None
        form_tags = request.form.get('tags').split()[0:5]
        bucket = 'post-pics'
        if post.photo:
            post.photo['nsfw'] = True if request.form.get('photo_nsfw') else False
        
        if request.form.get('tags') and post.tags:
            # list of current tag names
            post_tags = []
            for tag in post.tags:
                post_tags.append(tag.name)
            # filter old tags
            for tag in post.tags:
                if tag.name not in form_tags:
                    db.session.execute(sa.delete(Tag).where(Tag.id == tag.id))
                    db.session.execute(tags_tbl.delete().where(tags_tbl.c.tag_id == tag.id))
            # check for duplicate tags in form then add
            for tag in form_tags:
                if tag not in post_tags:
                    db.session.add(Tag(name=tag.replace('#', ''), posts=[post]))

        else:
            unique_tags = []
            # remove duplicates
            for tag in form_tags:
                if tag not in unique_tags:
                    unique_tags.append(tag)
                    db.session.add(Tag(name=tag.replace('#', ''), posts=[post]))

        photo_name = []
        photo_link = []

        if request.form.get('photo_link'):
            new_links = request.form.get('photo_link').split()[0:5]
            
            if post.photo and post.photo['link']:
                # delete old photos from DO Spaces
                old_links = post.photo['link']
                for i, f in enumerate(old_links):
                    if f not in new_links:
                        Post.delete_photo(f)
                        old_links.remove(f)
                # update list after removing old links
                post.photo['link'] = old_links
                
                for i, f in enumerate(new_links):
                    if f in post.photo['link']:
                        Post.delete_photo(f)
                    photo_name.append(f"photo{i + 1}")
                    photo_link.append(f)
                post.photo = {"name": photo_name, "link": photo_link}
            else:
                nsfw = True if request.form.get('photo_nsfw') else False
                for i, f in enumerate(photo_links):
                    photo_name.append(f"photo{i + 1}")
                    photo_link.append(f)
                nsfw = True if request.form.get('photo_nsfw') else False
                post.photo = {"name": photo_name, "link": photo_link, "nsfw": nsfw}

                
        photo_files = request.files.getlist('photo')[0:5] if request.files['photo'] else None
        if photo_files:
            update_photo = True if post.photo and post.photo['link'] else False
            if post.photo and post.photo['link']:
                for p in post.photo['link']:
                    Post.delete_photo(p)

            nsfw = True if request.form.get('photo_nsfw') else False
            for f in photo_files:
                if f.filename != '' and Photo.allowed_file(f.filename):
                    name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}-{current_user.username}-{current_user.id}-{f.filename}"
                    f.filename = secure_filename(f.filename)
                    if Photo.upload_object(bucket, name, f, 'public-read'):
                        photo_name.append(f.filename)
                        photo_link.append(f"{Photo.SPACES_URL}/{bucket}/{name}")

            if update_photo:
                post.photo = {"name": photo_name, "link": photo_link}
#                post.photo['name'] = photo_name
#                post.photo['link'] = photo_link
            else:
                post.photo = {"name": photo_name, "link": photo_link, "nsfw": nsfw}


        if request.form.get('delete_photo') and post.photo:
            for p in post.photo['link']:
                Post.delete_photo(p)
            post.photo = None

        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - edit_post()'))
            print(e)
        return redirect(url_for('main.post', id=post.id))

    elif request.form.get('submit') == 'delete_post':
        if post.user_id == current_user.id or current_user.can("MODERATE"):
            if post.photo:
                for p in post.photo['link']:
                    Post.delete_photo(p)

            if post.tags:
                for tag in post.tags:
                    # remove tag from post.tags list
                    post.tags.remove(tag)
                    db.session.execute(sa.delete(Tag).where(Tag.id == tag.id))

            # PRAGMA enables cascade in sqlite
            db.session.execute(sa.text('PRAGMA foreign_keys = ON'))
            post.delete_comments()
#            db.session.execute(sa.delete(Comment).where(Comment.post_id == id))
            db.session.delete(post)

            try:
                db.session.commit()
            except Exception as e:
                flash(_('DB Commit Fail - edit_post()'))
                print(e)                
            return redirect(url_for('main.index'))
            
    tags_value = ""
    for tag in post.tags:
        tags_value += tag.name + " "

    return render_template('edit_post.html', title=_('Edit Post - ') + f"{post.author.username }", post=post, tags=tags_value)

@bp.route('/post-comments/<int:id>', methods=['GET', 'POST'])
@login_required
def post_comments(id):
    if request.method == 'POST':
        comment = db.first_or_404(sa.select(Comment).where(Comment.id == id))
        post = db.session.execute(sa.select(Post).where(Post.id == comment.post_id)).scalar()
        if (current_user != comment.author and current_user != post.author) and not current_user.can("MODERATE"):
            return redirect(request.referrer)
        comment.disabled = True if request.form.get('submit') == 'disable' else False
        if request.form.get('submit') == 'delete':
            if comment.pinned and (current_user == post.author or current_user.can('MODERATE')):
                post.pin_comments -= 1
            db.session.delete(comment)

        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - post_comments()'))
            print(e)
        return redirect(request.referrer)

    post = db.first_or_404(sa.select(Post).where(Post.id == id))
#    query = sa.select(Comment).where(Comment.post_id == id).order_by(Comment.timestamp.desc())
    query = post.comments()    
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('post_comments.html', title=_('Post Comments - ') + f"{post.author.username }", post=post, comments=pagination.items, pagination=pagination)


@bp.route('/<username>/user-comments', methods=['GET', 'POST'])
@login_required
def user_comments(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    if request.method == 'POST':
        comment = db.first_or_404(sa.select(Comment).where(Comment.id == request.form.get('input_id')))
        post = db.session.execute(sa.select(Post).where(Post.id == comment.post_id)).scalar()
        if current_user != comment.author and not current_user.can("MODERATE"):
            return redirect(request.referrer)
        comment.disabled = True if request.form.get('submit') == 'disable' else False
        if request.form.get('submit') == 'delete':
            if comment.pinned and (current_user == post.author or current_user.can('MODERATE')):
                post.pin_comments -= 1
            db.session.delete(comment)

        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - user_comments()'))
            print(e)
        return redirect(request.referrer)

    query = user.comments.select().where(Comment.user_id == user.id).order_by(Comment.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('user_comments.html', title=_('User Comments - ') + f"{user.username }", comments=pagination.items, user=user, pagination=pagination)
  

#https://docs.sqlalchemy.org/en/20/orm/queryguide/select.html#joining-to-subqueries
@bp.route('/tags/<name>', methods=['GET'])
def view_tags(name):
    tag = db.first_or_404(sa.select(Tag).where(Tag.name == name))
    query = db.select(Post)\
            .join(tags_tbl, tags_tbl.c.post_id == Post.id)\
            .join(Tag, tags_tbl.c.tag_id == Tag.id)\
            .where(Tag.name == name)
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)

    return render_template('tags.html', title=_('Tags'), posts=pagination.items, pagination=pagination)


@bp.route('/<username>', methods=['GET', 'POST'])
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    if request.method == 'POST' and current_user.can("WRITE"):
        if request.form.get('submit') == 'follow':
            #Cannot follow yourself        
            if user is None or user == current_user:
                return redirect(request.referrer)
            current_user.follow(user)

        elif request.form.get('submit') == 'unfollow':
            #Cannot unfollow yourself
            if user is None or user == current_user:
                return redirect(request.referrer)
            current_user.unfollow(user)
            
        elif request.form.get('submit') == 'ping':
            payload = f"\n" + f"{request.form.get('body')}"
            db.session.add(Notification(user=user, name='new_notice', payload_json=payload, item_id=0, item_type='ping'))
        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - user()'))
            print(e)
        return redirect(request.referrer)            
        
    query = user.posts.select().order_by(Post.timestamp.desc())    
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False) 
    age = (datetime.now() - user.birth).days // 365 if user.birth else None
    
    return render_template('user.html',  title=_('User - ') + f"{user.username }", user=user, posts=pagination.items, pagination=pagination, age=age)


@bp.route('/<username>/followers', methods=['GET'])
def followers(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    query = user.followers.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)
            
    return render_template('followers.html',  title=_('Followers - ') + f"{user.username }", users=pagination.items, user=user, pagination=pagination)
    

@bp.route('/<username>/following', methods=['GET'])
def following(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    query = user.following.select().order_by(User.last_seen.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['FOLLOWS_PER_PAGE'], error_out=False)
        
    return render_template('following.html',  title=_('Following - ') + f"{user.username }", users=pagination.items, user=user, pagination=pagination)


@bp.route('/edit-account/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_account(id):
    user = current_user
    if request.method == 'POST' and user.id == id:
        if request.form.get('submit') == 'edit_account':
            bucket = 'profile-pics'
            user.song = request.form.get('song_name') + '^' + request.form.get('song_link') if request.form.get('song_name') and request.form.get('song_link') else None
            user.location = request.form.get('location')
            user.birth = datetime.strptime(request.form.get('birth'), '%Y-%m-%d') if request.form.get('birth') else None
            user.phone = request.form.get('phone')
            user.about_me = request.form.get('about_me')
            if request.form.get('picture_link'):
                if user.picture and request.form.get('picture_link') != user.picture:
                    user.delete_photo()
                    user.picture = request.form.get('picture_link') if request.form.get('picture_link') != 'null' else None
                else:
                    user.picture = request.form.get('picture_link')

            f = request.files['picture']
            if f.filename != '' and Photo.allowed_file(f.filename):
                if user.picture:
                    user.delete_photo()

                name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}-{user.username}-{f.filename}"
                f.filename = secure_filename(f.filename)
                if Photo.upload_object(bucket, name, f, 'public-read'):
                    user.picture = f"{Photo.SPACES_URL}/{bucket}/{name}"
            try:
                db.session.commit()                        
            except:
                flash(_('Invalid input. Check Unique email'))
            return redirect(request.referrer)
            
        elif request.form.get('submit') == 'enable_mfa':
            user.set_otp_secret()
        
        elif request.form.get('submit') == 'disable_mfa':
            user.otp_secret = None
            user.mfa_enabled = False

        elif request.form.get('submit') == 'check_token':
            if user.check_totp(request.form.get('mfa_token')):
                user.mfa_enabled = True

        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - edit_account()'))
            print(e)
        return redirect(url_for('main.user', username=user.username))            
            
    birth = datetime.strftime(user.birth, '%Y-%m-%d') if user.birth else None
        
    return render_template('edit_account.html', title=_('Edit account - ') + f"{user.username}", user=current_user, birth=birth)


@bp.route('/edit-account-admin/<username>', methods=['GET', 'POST'])
@login_required
@permission_required('MODERATE')
def edit_account_admin(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    if request.method == 'POST':
        if request.form.get('submit') == 'edit_account':
            if user.email != request.form.get('email') and not db.session.execute(sa.select(User).where(User.email == request.form.get('email'))).scalar():
                user.email = request.form.get('email') if current_user.can('ADMIN') else user.email
            user.about_me = request.form.get('about_me')
            user.confirmed = True if request.form.get('confirmed') else False
            user.verified = True if request.form.get('verified') else False
            user.disabled = True if request.form.get('disabled') and current_user.can('ADMIN') else False
            user.label = request.form.get('label')
            user.song = request.form.get('song_name') + '^' + request.form.get('song_link')
            user.location = request.form.get('location') if request.form.get('location') else None
            # Admin cannot set a permission above their own            
            if int(request.form.get('permission')) <= current_user.permission:   
                if current_user.can('ADMIN'):
                    user.set_permission(Permission(int(request.form.get('permission'))).name)
                # Moderator can only set permission below their own                    
                elif int(request.form.get('permission')) < current_user.permission:
                    user.set_permission(Permission(int(request.form.get('permission'))).name)

            if request.form.get('picture_link'):
                if user.picture and request.form.get('picture_link') != user.picture:
                    user.delete_photo()
                    user.picture = request.form.get('picture_link') if request.form.get('picture_link') != 'null' else None
                else:
                    user.picture = request.form.get('picture_link')

        if request.form.get('submit') == 'set_admin_token' and current_user.can('ADMIN'):
            user.set_admin_token()

        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - edit_account_admin()'))
            print(e)
        return redirect(url_for('main.user', username=user.username))
            
    return render_template('edit_account_admin.html', title=_('Edit account admin - ') + f"{user.username}", username=user.username, user=user)


@bp.route('/delete-account/<int:id>', methods=['POST'])
@login_required
def delete_account(id):
    user = db.first_or_404(sa.select(User).where(User.id == id))
    if user is None or current_user.id != user.id and not current_user.can('ADMIN'):
        return redirect(url_for('main.index'))
    elif user.check_password(request.form.get('password')) or current_user.check_password(request.form.get('password')):
        if user.picture:
            user.delete_photo()
        # Delete post photos from storage Spaces
        posts = db.session.execute(user.posts.select()).scalars()
        for p in posts:
            p.delete_comments()
            p.delete_photos()

        messages = db.session.execute(user.messages_sent.select()).scalars()
        for m in messages:
            if m.photo:
                name = message.photo.removeprefix(f"{Photo.SPACES_URL}/message-pics/")
                Photo.delete_object(bucket, name)

        # PRAGMA enables cascade in sqlite
        db.session.execute(sa.text('PRAGMA foreign_keys = ON'))
        db.session.execute(user.messages_sent.delete())
        db.session.execute(user.comments.delete())
        db.session.execute(user.votes.delete())
        db.session.execute(user.flags.delete())
        db.session.execute(user.notifications.delete())
        db.session.execute(user.posts.delete())
        db.session.execute(follows_tbl.delete().where((follows_tbl.c.follower_id == user.id) | (follows_tbl.c.followed_id == user.id)))
        db.session.delete(user)

        try:
            db.session.commit()
            return redirect(url_for('main.index'))
        except Exception as e:
            flash(_('DB Commit Fail - delete_account()'))
            print(e)            
            return redirect(request.referrer)
    else:
        flash(_('Invalid'))
        return redirect(request.referrer)  
    

@bp.route('/inbox')
@login_required
@permission_required('MESSAGE')
def inbox():
    current_user.last_message_read_time = datetime.now(timezone.utc)
    db.session.execute(current_user.notifications.update().where((Notification.user_id == current_user.id) & (Notification.name == 'unread_message_count')).values(payload_json=0, timestamp=datetime.now(timezone.utc)))
    
    try:
        db.session.commit()
    except Exception as e:
        flash(_('DB Commit Fail - inbox()'))
        print(e)
        return redirect(request.referrer)

    query = sa.select(Message, sa.func.max(Message.timestamp)).where((Message.recipient_id == current_user.id) | (Message.sender_id == current_user.id)).group_by(Message.sender_id, Message.recipient_id).order_by(Message.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    return render_template('inbox.html', title=_('Inbox - ') + f"{current_user.username}" , messages=pagination.items, pagination=pagination)


#https://docs.sqlalchemy.org/en/20/tutorial/data_select.html
#https://docs.sqlalchemy.org/en/20/core/operators.html
@bp.route('/message/<username>', methods=['GET', 'POST'])
@login_required
@permission_required('MESSAGE')
def message(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    if request.method == 'POST':
        msg = Message(sender=current_user, recipient=user, _body=request.form.get('body'))
        db.session.add(msg)    
        if request.files['photo'].filename:
            f = request.files['photo']
            bucket = 'message-pics'
            if Photo.allowed_file(f.filename):
                name = f"{uuid.uuid4()}"
                f.filename = secure_filename(f.filename)
                if Photo.upload_object(bucket, name, f, 'private'):
                    msg.photo = f"{Photo.SPACES_URL}/{bucket}/{name}"

        try:
            db.session.commit()
            message = db.session.execute(user.messages_received.select().where(Message.sender == current_user).order_by(Message.id.desc())).scalar()
            return {
                "body": message._body,
                "timestamp": message.timestamp,
                "photo": Photo.get_url(message.photo.removeprefix(f"{Photo.SPACES_URL}/message-pics/")) if message.photo else None
            }        
        except Exception as e:
            flash(_('DB Commit Fail - message()'))
            print(e)
            return redirect(request.referrer)

    current_user.last_message_read_time = datetime.now(timezone.utc)
    db.session.commit()
    query = sa.select(Message).where((Message.sender == current_user) & (Message.recipient == user) | (Message.sender == user) & (Message.recipient == current_user)).order_by(Message.timestamp.asc())
    messages = db.session.execute(query).scalars()

    return render_template('message.html', title=_('Messages'), messages=messages, sender=user)


@bp.route('/edit-messages', methods=['GET', 'POST'])
@login_required
def edit_messages():
    if request.method == 'POST':
        message = db.first_or_404(sa.select(Message).where(Message.id == request.form.get('input_id')))
        if current_user != message.sender:
            return redirect(request.referrer)
        if message.photo:
            bucket = 'message-pics'
            name = message.photo.removeprefix(f"{Photo.SPACES_URL}/{bucket}/")
            Photo.delete_object(bucket, name)
        db.session.delete(message)
        
        try:
            db.session.commit()
        except Exception as e:
            flash(_('DB Commit Fail - edit_messages()'))
            print(e)
        return redirect(request.referrer)
    
    query = current_user.messages_sent.select().order_by(Message.timestamp.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    
    return render_template('edit_messages.html', title=_('Edit Messages'), messages=pagination.items, pagination=pagination)


@bp.route('/view-notifications', methods=['GET', 'POST'])
@login_required
def view_notifications():
    current_user.last_notification_read_time = datetime.now(timezone.utc)
    if request.method == 'POST':
        db.session.execute(current_user.notifications.delete().where(Notification.id == request.form.get('input_id')))
        
    try:
        db.session.commit()
    except Exception as e:
        flash(_('DB Commit Fail - view_notifications()'))
        print(e)

    query = current_user.notifications.select().where((Notification.item_type == 'comment') | (Notification.item_type == 'ping')).order_by(Notification.id.desc())
    pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['COMMENTS_PER_PAGE'], error_out=False)

    return render_template('view_notifications.html', title=_('View notifications - ') + f"{current_user.username}", notifications=pagination.items, pagination=pagination)


@bp.route('/notifications')
@login_required
def notifications():
    since = request.args.get('since', 0.0, type=float)
    query = current_user.notifications.select().where(Notification.timestamp > since).order_by(Notification.timestamp.asc())
    notifications = db.session.execute(query).scalars()
       
    try:
        return [{
            'name': n.name,
            'data': n.get_data(),
            'timestamp': n.timestamp.timestamp()
        } for n in notifications]
    except:
        return {}


#https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.ColumnElement.icontains
@bp.route('/search')
def search():
    q = request.args.get('q')
    if q:
        query = sa.select(Post).where(Post.title.icontains(q) | Post.body.icontains(q)).order_by(Post.timestamp.desc()).limit(20)
        pagination = db.paginate(query, page=request.args.get('page', 1, type=int), per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    else:
        return redirect(request.referrer)
    return render_template('search.html', title=_('Search'), posts=pagination.items, pagination=pagination, q=q)


@bp.route('/chatii', methods=['GET', 'POST'])
@login_required
def chatii():
    if request.method == 'POST':
        name = request.form.get('name') if request.form.get('name') == current_user.username else f"~{request.form.get('name')}~"
        code = request.form.get('code')
        join = request.form.get('join', False)
        create = request.form.get('create', False)
              
        if not name:
            return render_template('chatii.html', title=_('Chatii'), err_msg=_('Enter name'), code=code, name=name)
            
        if join != False and not code:
            return render_template('chatii.html', title=_('Chatii'), err_msg=_('Enter code'), code=code, name=name)
            
        room = code
        if create != False and current_user.is_authenticated:
            room = Chatii.generate_room_code(6)
            Chatii.rooms[room] = {"members": 0, "messages": [], "time": None}
        elif code not in Chatii.rooms:
            return render_template('chatii.html', err_msg=_('Not found'), code=code, name=name)
            
        session['name'] = name
        session['room'] = room
        return redirect(url_for('main.room'))
    return render_template('chatii.html', title=_('Chatii'))


@bp.route('/chatii-room')
@login_required
def room():
    room = session.get('room')
    if room is None or session.get('name') is None or room not in Chatii.rooms:
        return redirect(url_for('main.chatii'))
        
    return render_template('chatii_room.html', title=_('Chatii Room'), code=room, messages=Chatii.rooms[room]['messages'][-10:])


@socketio.on('message')
def message(data):
    room = session.get('room')
    if room not in Chatii.rooms:
        return
    time = datetime.now(timezone.utc).timestamp() * 1000
    content = {
        "name": session.get("name"),
        "body": data["body"],
        "img": data["img"],
        "time": time
    }

    send(content, to=room)
    Chatii.rooms[room]["messages"][-10:]
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


@bp.route('/about', methods=['GET'])
def about():
    return render_template('about.html', title=_('About'))


@bp.route('/contact', methods=['GET'])
def contact():
    return render_template('contact.html', title=_('Contact'))


@bp.route('/promote', methods=['GET'])
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
#        print(e)
#    return redirect(url_for('main.user', username=current_user.username))
