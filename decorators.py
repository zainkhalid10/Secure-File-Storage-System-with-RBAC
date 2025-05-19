# decorators.py

from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def role_required(roles):
    if not isinstance(roles, (list, tuple)):
        roles = [roles]
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                flash('Unauthorized access', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return decorator
