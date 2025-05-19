from flask import abort
from flask_login import current_user
from functools import wraps

def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)
            if current_user.role not in allowed_roles:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapper
    return decorator

