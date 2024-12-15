import jwt
from datetime import datetime, timedelta
from flask import request, jsonify
from functools import wraps

SECRET_KEY = 'Pandurangasao'
def create_token(username,additional_claims=None):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=2)  
    }
    if additional_claims:
        payload.update(additional_claims)
    
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def decode_token(token):
    """Decode a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload  
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

def token_required(f):
    """Decorator to protect routes that require authentication."""
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token is missing"}), 401

        token = token.split(" ")[1] if " " in token else token
        decoded = decode_token(token)
        if "error" in decoded:
            return jsonify({"message": decoded["error"]}), 401

        kwargs["username"] = decoded.get("username")
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper
