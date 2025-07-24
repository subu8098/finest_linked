import jwt
from datetime import datetime, timedelta

# Secret key (in production, keep this in environment variable)
JWT_SECRET = 'subu_super_secret'
JWT_ALGORITHM = 'HS256'

def generate_jwt(user_id, minutes=None, days=None):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + (
            timedelta(minutes=minutes) if minutes else timedelta(days=days)
        ),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


from .models import BlacklistedToken

def decode_jwt(token):
    try:
        # Check if blacklisted
        if BlacklistedToken.objects.filter(token=token).exists():
            print("Token is blacklisted")
            return None

        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

