from flask import request
from flask_wtf import FlaskForm
from flask_babel import _, lazy_gettext as _l
from wtforms import  BooleanField, FileField, StringField, SubmitField, TextAreaField, SelectField, MultipleFileField
from wtforms.validators import ValidationError, DataRequired, Email, Length, Regexp
import sqlalchemy as sa
from app import db
from app.models import User


class EditAccountForm(FlaskForm):
    name = StringField(_l('User name'), validators=[Length(0, 64)])
    location = StringField(_l('Location'), validators=[Length(0, 64)])    
    about_me = TextAreaField(_l('About me'))
#    photo = FileField(_l('Photo'))  
    submit = SubmitField(_l('Submit'))


class EditAccountAdminForm(FlaskForm):
    email = StringField(_l('Email'), validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField(_l('Username'), validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    confirmed = BooleanField(_l('Confirmed'))
    role = SelectField(_l('Role'), coerce=int)
    name = StringField(_l('Real name'), validators=[Length(0, 64)])
    location = StringField(_l('Location'), validators=[Length(0, 64)])
    about_me = TextAreaField(_l('About me'))
    submit = SubmitField(_l('Submit'))

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in sa.select(Role).order_by(Role.name.desc()).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and sa.select(User).filter_by(email=field.data).first(): 
            raise ValidationError(_('Use a different email'))

    def validate_username(self, field):
        if field.data != self.user.username and sa.select(User).filter_by(username=field.data).first():
            raise ValidationError(_('Use a different username'))


class EmptyForm(FlaskForm):
    submit = SubmitField(_l('Submit'))


class FileForm(FlaskForm):
    photo = FileField(_l('Photo'))


class SubmitForm(FlaskForm):
    submit = SubmitField(_l('Submit'))


class PostForm(FlaskForm):
    body = TextAreaField((''), validators=[DataRequired()])
    tags = StringField(_l('Tags:'), validators=[Length(0, 100)])
    photo = FileField(_l('Photo'))
    submit = SubmitField(_l('Submit'))


class MessageForm(FlaskForm):
    message = TextAreaField(_l('Message'), validators=[
        DataRequired(), Length(min=0, max=1000)])
    submit = SubmitField(_l('Submit'))

class MessageReplyForm(FlaskForm):
    message = TextAreaField(_l('Message'), validators=[
        DataRequired(), Length(min=0, max=1000)])
    submit = SubmitField(_l('Reply'))

class CommentForm(FlaskForm):
    body = TextAreaField('', validators=[DataRequired(), Length(min=0, max=1000)])
    submit = SubmitField(_l('Submit'))


class SearchForm(FlaskForm):
    q = StringField(_l('Search'), validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        if 'formdata' not in kwargs:
            kwargs['formdata'] = request.args
        if 'meta' not in kwargs:
            kwargs['meta'] = {'csrf': False}
        super(SearchForm, self).__init__(*args, **kwargs)
