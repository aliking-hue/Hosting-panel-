from flask import session, redirect, url_for, request, jsonify
from functools import wraps
import os

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_auth(username, password):
    """Check if username/password combination is valid"""
    # In production, use proper authentication
    # For demo, using environment variables
    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    return username == admin_user and password == admin_pass
