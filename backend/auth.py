# Authentication utilities
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from config import Config
from models import User, db
from utils.logger import log_login_attempt, log_user_action

def _get_jwt_secret():
    """Return the JWT secret from the active Flask app config or the module-level Config.

    Raises RuntimeError if no secret has been configured, ensuring that the
    application cannot start (or process requests) without a proper secret.
    """
    try:
        from flask import current_app
        secret = current_app.config.get('JWT_SECRET_KEY')
    except RuntimeError:
        # No active application context — fall back to the class-level config.
        secret = Config.JWT_SECRET_KEY
    if not secret:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable must be set to a strong secret value."
        )
    return secret

def generate_token(user_id, username):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'iat': datetime.utcnow(),
    }

    token = jwt.encode(payload, _get_jwt_secret(), algorithm=Config.JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=[Config.JWT_ALGORITHM])
        return payload
    except jwt.InvalidTokenError:
        return None

def get_current_user():
    """Get current user from token"""
    token = None
    
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = auth_header
    
    if not token:
        token = request.args.get('token')
    
    if not token:
        token = request.form.get('token')
    
    if not token:
        return None
    
    payload = verify_token(token)
    if not payload:
        return None
    
    user = User.query.get(payload.get('user_id'))
    return user

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            if user.role == 'admin':
                return f(*args, **kwargs)
            
            if required_role == 'project_manager' and user.role in ['admin', 'project_manager']:
                return f(*args, **kwargs)
            
            if user.role != required_role:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

