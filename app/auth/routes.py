from app import db
from app.auth import bp
from app.auth.email import send_password_reset_email, send_confirm_account_email, send_change_email, send_admin_token_email
from app.email import send_email
from app.models import User
from datetime import datetime, timezone
from flask import render_template, flash, redirect, request, url_for
from flask_login import current_user, login_user, logout_user, login_required
from flask_babel import _
from io import BytesIO
from urllib.parse import urlsplit
import sqlalchemy as sa
import qrcode
import qrcode.image.svg



#https://stackoverflow.com/questions/15974730/how-do-i-get-the-different-parts-of-a-flask-requests-url/46176337#46176337
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        if request.form.get('submit') == 'login':
            user = db.session.execute(sa.select(User).where(User.username == request.form.get('username'))).scalar()
            if user is None or not user.check_password(request.form.get('password')):
                return redirect(url_for('auth.login'))
            if user.disabled:
                flash(_('Account disabled'))
                return redirect(url_for('main.index'))                
            if user and user.mfa_enabled:
                return render_template('auth/login_mfa.html', title=_('MFA Login'), user=user)
            login_user(user, remember=request.form.get('remember_me'))
            next_page = request.args.get('next')
            if not next_page or urlsplit(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)
        elif request.form.get('submit') == 'login_mfa':
            user = db.session.execute(sa.select(User).where(User.id == request.form.get('user_id'))).scalar()        
            if user is None or not user.check_totp(request.form.get('mfa_token')) and user.admin_token != request.form.get('mfa_token'):
                return redirect(url_for('auth.login'))
            if user.admin_token == request.form.get('mfa_token'):
                user.admin_token = None
                try:
                    db.session.commit()
                except:
                    flash(_('DB Commit Failed'))                
                    pass
            login_user(user, remember=request.form.get('remember_me'))
            next_page = request.args.get('next')
            if not next_page or urlsplit(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)
    return render_template('auth/login.html', title=_('Sign In'))


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user = db.session.execute(sa.select(User).where(User.username == request.form.get('username'))).scalar()
        if user:
            flash(_('username exist'))
        if request.form.get('password') != request.form.get('password2'):
            flash(_('Passwords must match'))
            return redirect(request.referrer)
        else:
            user = User(username=request.form.get('username').lower(), email=request.form.get('email').lower(), joined=datetime.now(timezone.utc))
            user.set_password(request.form.get('password'))
        db.session.add(user)
        try:
            db.session.commit()
        except:
            flash(_('DB Commit Failed'))
            return redirect(request.referrer)
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title=_('Register'))


#https://flask.palletsprojects.com/en/3.0.x/quickstart/#about-responses
@bp.route('/setup-mfa')
@login_required
def setup_mfa():
    return render_template('auth/setup_mfa.html', title=_('Setup MFA')), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@bp.route('/show-qr')
@login_required
def show_qr():
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )

    qr.add_data(current_user.get_totp_uri())
    qr.make(fit=True)
    
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathFillImage)
    
    # save qr to stream buffer
    stream = BytesIO()
    img.save(stream)
    stream.seek(0)
    
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@bp.route('/request-admin-token/<int:id>', methods=['POST'])
def request_admin_token(id):
    user = db.session.execute(sa.select(User).where(User.id == id)).scalar()
    if user:
        user.set_admin_token()
        db.session.add(user)
        try:
            db.session.commit()
        except:
            flash(_('DB Commit Failed'))
            pass
        send_admin_token_email(user=user)    
    return redirect(url_for('main.index'))


@bp.route('/request-confirm-account')
@login_required
def request_confirm_account():
    if current_user.confirmed:
        return redirect(request.referrer)
    send_confirm_account_email(current_user)
    flash(_('Email sent'))    
    return redirect(request.referrer)


@bp.route('/confirm-account/<token>')
def confirm_account(token):
    if current_user.is_authenticated and current_user.confirmed:
        return redirect(url_for('main.index'))
    user = User.confirm_token(token)
    if user:
        user.confirm = True
        db.session.add(user)
        try:
            db.session.commit()
        except:
            flash(_('DB Commit Failed'))
            pass
    else:
        flash(_('Invalid'))
    return redirect(url_for('main.index'))


@bp.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user = db.session.execute(sa.select(User).where(User.email == request.form.get('email'))).scalar()
        if user:
            send_password_reset_email(user)
        else:
            return redirect(request.referrer)
        return redirect(url_for('auth.login'))
    return render_template('auth/request_password_reset.html', title=_('Request Password Reset'))


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user.set_password(request.form.get('password'))
        try:
            db.session.commit()
        except:
            flash(_('DB Commit Failed'))
            pass
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', title=_('Reset Password'))


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if current_user.check_password(request.form.get('old_password')):
            if request.form.get('password') == request.form.get('password2'):
                current_user.set_password(request.form.get('password'))
                db.session.add(current_user)
                try:
                    db.session.commit()
                except:
                    flash(_('DB Commit Failed'))
                    pass
                return redirect(url_for('main.user', username=current_user.username))
        else:
            flash(_('Invalid'))
    return render_template('auth/change_password.html', title=_('Change Password'))


@bp.route('/request-change-email', methods=['GET', 'POST'])
@login_required
def request_change_email():
    if request.method == 'POST':
        if current_user.check_password(request.form.get('password')):
            user = current_user
            email = request.form.get('email').lower()
            send_change_email(user, email)
            return redirect(url_for('main.user', username=current_user.username))
        else:
            flash(_('Invalid'))
    return render_template('auth/change_email.html', title=_('Change Email'))


@bp.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.verify_change_email_token(token):
        try:
            db.session.commit()
        except:
            flash(_('DB Commit Failed'))
            pass
    return redirect(url_for('main.user', username=current_user.username))
