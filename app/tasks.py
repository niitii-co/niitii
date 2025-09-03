from app import create_app
from app.email import send_email
from app.models import Task, User, Post
from flask import render_template
from rq import get_current_job
import time


# Flask application instance will provide the configuration
app = create_app()
# RQ worker needs an an application instance for task functions.
# app_context() makes the application be the current instance. Enables Flask-SQLAlchemy to use current_app.config to obtain configs.
app.app_context().push()


# check if progress is completed. Update the complete attribute of Task object.
def _set_task_progress(progress):
    job = get_current_job()
    if job:
        job.meta['progress'] = progress
        job.save_meta()
        task = db.session.get(Task, job.get_id())
        task.user.add_notification('task_progress', {'task_id': job.get_id(), 'progress': progress})
        if progress >= 100:
            task.complete = True
        db.session.commit()


# RQ normally displays errors to the console and waits for new jobs. This function writes RQ erros to a log file.
# Try: issues a DB query, walks thru results in a loop, adds results in a dictionary. Time is in ISO 8601. datetime object does not store timezone. Adding 'Z' indicates UTC.
# time.sleep(5) makes the export task last longer so that the progress can display to users
# except: Flask logger object will log the error along with the stack trace, which is provided by sys.exc_info().
def export_posts(user_id):
    try:
        user = db.session.get(User, user_id)
        _set_task_progress(0)
        data = []
        i = 0
        total_posts = db.session.scalar(sa.select(sa.func.count()).select_from(user.posts.select().subquery()))
        for post in db.session.scalars(user.posts.select().order_by(Post.timestamp.asc())):
            data.append({'body': post.body, 'timestamp': post.timestamp.isoformat() + 'Z'})
            time.sleep(5)
            i += 1
            _set_task_progress(100 * i // total_posts)
        send_email(
            '[Niitii] Your blog posts',
            sender=app.config['MAIL_SENDER'], recipients=[user.email],
            text_body=render_template('email/export_posts.txt', user=user),
            html_body=render_template('email/export_posts.html', user=user),
            attachments=[('posts.json', 'application/json', json.dumps({'posts': data}, indent=4))], sync=True)
    except Exception:
        _set_task_progress(100)
        app.logger.error('Unhandled exception', exc_info=sys.exc_info())
    finally:
        _set_task_progress(100)

