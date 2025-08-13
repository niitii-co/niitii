import sqlalchemy as sa
import sqlalchemy.orm as so
from app import create_app, db, socketio
from app.models import User, Post, Comment, Message, Notification, Task

app = create_app()

if __name__ == '__main__':
    socketio.run(app)

@app.shell_context_processor
def make_shell_context():
    return {'sa': sa, 'so': so, 'db': db, 'User': User, 'Post': Post, 'Comment':Comment,
            'Message': Message, 'Notification': Notification, 'Task': Task}

