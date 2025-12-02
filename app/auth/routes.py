from app import db
from app.auth import bp
from app.auth.email import send_password_reset_email, send_confirm_account_email, send_change_email, send_admin_token_email
from app.decorators import permission_required
from app.email import send_email
from app.models import User
from datetime import datetime, timezone, timedelta
from flask import render_template, flash, redirect, request, url_for, json
from flask_login import current_user, login_user, logout_user, login_required
from flask_babel import _
from io import BytesIO
from urllib.parse import urlsplit
import sqlalchemy as sa
import qrcode
import qrcode.image.svg


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        # Validate if form is sent from human
        if not request.form.get('csrf_token') or not request.form.get('start_time') or request.form.get('name') != '':
            return redirect('http://localhost')

        # Time based validation
        start_time = datetime.fromisoformat(request.form.get('start_time'))
        time_elapsed = datetime.now() - start_time
        if time_elapsed < timedelta(seconds=3) or time_elapsed > timedelta(seconds=600):
            return redirect('http://localhost')

        user = User.query_user(request.form.get('username'), True)
        if user is None or not user.check_password(request.form.get('password')):
            return redirect(url_for('auth.login'))
        if user.disabled:
            flash(_('Account disabled'))
            return redirect(url_for('main.index'))
        if user and user.mfa_enabled:
            if not request.form.get('mfa_token') or not user.check_totp(int(request.form.get('mfa_token'))) and user.admin_token != int(request.form.get('mfa_token')):
                flash(_('Invalid token'))
                return redirect(url_for('auth.login'))
            if user.admin_token != None:
                user.admin_token = None
            db.session.commit()
        user.language = request.form.get('language') if request.form.get('language') else 'en-US'
        user.utc_offset = request.form.get('utc_offset') if request.form.get('utc_offset') else 0
        db.session.commit()
        login_user(user, remember=request.form.get('remember_me'))
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
            
    start_time = datetime.now().isoformat()
    return render_template('auth/login.html', title=_('Sign In'), start_time=start_time)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        # Validate if form is sent from human
        if not request.form.get('csrf_token') or not request.form.get('start_time') or request.form.get('name') != '':
            return redirect('http://localhost')

        # Time based validation
        start_time = datetime.fromisoformat(request.form.get('start_time'))
        time_elapsed = datetime.now() - start_time
        if time_elapsed < timedelta(seconds=10) or time_elapsed > timedelta(seconds=600):
            return redirect('http://localhost')

        user = User.query_user(request.form.get('username'), True)
        if user:
            flash(_('username exist'))
            return redirect(request.referrer)
        email = User.query_email(request.form.get('email'), True)
        if email:
            flash(_('email exist'))
            return redirect(request.referrer)
        if request.form.get('password') != request.form.get('password2'):
            flash(_('Passwords must match'))
            return redirect(request.referrer)
        else:
            user = User(username=request.form.get('username'), email=request.form.get('email'), joined=datetime.now(timezone.utc))
            user.set_password(request.form.get('password'))
            db.session.add(user)

        db.session.commit()
        return redirect(url_for('auth.login'))

    start_time = datetime.now().isoformat()
    return render_template('auth/register.html', title=_('Register'), start_time=start_time)


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


@bp.route('/show-mypage-qr')
@login_required
def show_mypage_qr():
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=20,
        border=4,
    )

    qr.add_data(f"{url_for('main.user', username=current_user.username, _external=True)}")
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


@bp.route('/mypage-qr')
@login_required
def mypage_qr():
    return render_template('auth/mypage_qr.html', title=_('My Page')), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@bp.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    if request.method == 'POST':
        if current_user.check_totp(request.form.get('mfa_token')):
            current_user.mfa_enabled = True
            db.session.commit()
            return redirect(url_for('main.user', username=current_user.username))

    current_user.set_otp_secret()
    db.session.commit()

    return render_template('auth/setup_mfa.html', title=_('Setup MFA')), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@bp.route('/disable-mfa', methods=['POST'])
@login_required
def disable_mfa():
    current_user.mfa_enabled = False
    current_user.otp_secret = None
    db.session.commit()

    return redirect(url_for('main.user', username=current_user.username))


@bp.route('/set-admin-token/<username>', methods=['POST'])
@permission_required('MODERATE')
@login_required
def set_admin_token(username):
    user = User.query_user(username, True)

    if user is None:
        return redirect(request.referrer)

    if user.mfa_enabled:
        user.set_admin_token()
        db.session.commit()

    return redirect(request.referrer)


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
        user.confirmed = True
        db.session.commit()
        flash(_('Confirmed'))        
    else:
        flash(_('Invalid'))
    return redirect(url_for('main.index'))


@bp.route('/request-admin-token', methods=['GET', 'POST'])
def request_admin_token():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user = User.query_user(request.form.get('username'), True)    
        if user is None or not user.mfa_enabled:
            return redirect(url_for('auth.login'))
        user.set_admin_token()
        db.session.commit()
        send_admin_token_email(user=user)
        flash(_('Email sent'))
        return redirect(url_for('main.index'))
    return render_template('auth/request_admin_token.html', title=_('Request Admin Token'))


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


@bp.route('/request-change-email', methods=['GET', 'POST'])
@login_required
def request_change_email():
    if request.method == 'POST':
        email = User.query_email(request.form.get('email'), True)
        if email:
            flash(_('email exist'))
            return redirect(request.referrer)
        if current_user.check_password(request.form.get('password')):
            user = current_user
            email = request.form.get('email')
            send_change_email(user, email)
            return redirect(url_for('main.user', username=current_user.username))
        else:
            flash(_('Invalid'))
    return render_template('auth/change_email.html', title=_('Change Email'))


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if current_user.check_password(request.form.get('old_password')) and request.form.get('password') == request.form.get('password2'):
            current_user.set_password(request.form.get('password'))
            db.session.commit()
            flash(_('New password'))
            return redirect(url_for('main.user', username=current_user.username))
        else:
            flash(_('Invalid'))
    return render_template('auth/change_password.html', title=_('Change Password'))


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        logout_user()
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        user.set_password(request.form.get('password'))
        db.session.commit()
        flash(_('New password'))
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', title=_('Reset Password'))


@bp.route('/change-email/<token>')
@login_required
def change_email(token):
    email = current_user.verify_change_email_token(token)
    if email:
        current_user.email = email
        db.session.commit()
        flash(_('New email'))
    return redirect(url_for('main.user', username=current_user.username))
