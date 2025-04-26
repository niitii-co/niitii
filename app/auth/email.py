from flask import render_template, current_app
from flask_babel import _
from app.email import send_email


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email(_('[niitii] Reset Your Password'),
               sender=current_app.config['MAIL_SENDER'],
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt', user=user, token=token),
               html_body=render_template('email/reset_password.html', user=user, token=token))


def send_confirm_account_email(user):
    token = user.generate_confirmation_token()
    send_email(_('[niitii] Confirm Account'),
               sender=current_app.config['MAIL_SENDER'],
               recipients=[user.email],
               text_body=render_template('email/confirm_account.txt', user=user, token=token),
               html_body=render_template('email/confirm_account.html', user=user, token=token))


def send_change_email(user, email):
    email = user.generate_change_email_token(email)
    send_email(_('[niitii] Confirm Email'),
               sender=current_app.config['MAIL_SENDER'],
               recipients=[user.email],
               text_body=render_template('email/change_email.txt', user=user, token=email),
               html_body=render_template('email/change_email.html', user=user, token=email))


def send_admin_token_email(user):
    token = user.admin_token
    send_email(_('[niitii] Admin Token'),
               sender=current_app.config['MAIL_SENDER'],
               recipients=[user.email],
               text_body=render_template('email/admin_token.txt', user=user, token=token),
               html_body=render_template('email/admin_token.html', user=user, token=token))
