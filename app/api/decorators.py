from app.errors import bad_request
from flask import g
from functools import wraps


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not g.current_user.can(permission):
                return bad_request('No permission')
            return f(*args, **kwargs)
        return decorated_function
    return decorator
