import os
import time
import jwt
from flask import request
from functools import wraps

JWT_SECRET = os.environ.get("JWT_SECRET", "changeme")
JWT_ALG = "HS256"
TOKEN_TTL = 60 * 60  # 1 hour

# Demo-only user store
USERS = {"analyst": "password123"}

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return {"error": "Missing or invalid Authorization header"}, 401
        token = auth.split(" ", 1)[1]
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
            request.user = decoded.get("sub")
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}, 401
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        return f(*args, **kwargs)
    return wrapper


def validate_user(username: str, password: str) -> bool:
    return USERS.get(username) == password