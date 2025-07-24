from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from user.models import User
import json
import bcrypt

@csrf_exempt
def register_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))

        name = body.get('name')
        email = body.get('email')
        password = body.get('password')

        # 1. Check all required fields
        if not all([name, email, password]):
            return JsonResponse({'error': 'Name, Email and Password are required'}, status=400)

        # 2. Check if email already exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=409)

        # 3. Hash the password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # 4. Create and save the user
        user = User(name=name, email=email, password=hashed_pw.decode('utf-8'))
        user.save()

        return JsonResponse({'message': 'User registered successfully'}, status=201)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def login_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))
        email = body.get('email')
        password = body.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and Password required'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

        # Compare password using bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

        # Generate token
        from .auth import generate_jwt
        token = generate_jwt(user.id, minutes=15)

        return JsonResponse({
            'message': 'Login successful',
            'token': token
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def login_userr(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))
        email = body.get('email')
        password = body.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and Password required'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

        # Compare password using bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

        # Generate token
        from .auth import generate_jwt
        access_token = generate_jwt(user.id, minutes=15)
        refresh_token = generate_jwt(user.id, days=7)  # For simplicity, using same function
        return JsonResponse({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def user_profile(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)

    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return JsonResponse({'error': 'Authorization header missing'}, status=401)

    try:
        # Example format: Bearer <token>
        token = auth_header.split(' ')[1]

        from .auth import decode_jwt
        decoded = decode_jwt(token)
        
        if decoded is None:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        user_id = decoded['user_id']

        from .models import User
        try:
            user = User.objects.get(id=user_id, is_deleted=False)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        return JsonResponse({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'about': user.about,
            'created_at': user.created_at,
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def update_user_profile(request):
    if request.method != 'PUT':
        return JsonResponse({'error': 'Only PUT method allowed'}, status=405)

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return JsonResponse({'error': 'Authorization header missing'}, status=401)

    try:
        token = auth_header.split(' ')[1]
        from .auth import decode_jwt
        decoded = decode_jwt(token)
        if decoded is None:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        user_id = decoded['user_id']
        user = User.objects.get(id=user_id, is_deleted=False)

        data = json.loads(request.body)

        name = data.get('name')
        about = data.get('about')
        profile_image = data.get('profile_image')

        # Update only if provided
        if name is not None:
            user.name = name
        if about is not None:
            user.about = about
        if profile_image is not None:
            user.profile = profile_image

        user.updated_at = timezone.now()  # Update the timestamp
        user.save()

        return JsonResponse({'message': 'Profile updated successfully'})

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def logout_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return JsonResponse({'error': 'Authorization header missing'}, status=401)

    try:
        token = auth_header.split(' ')[1]
        from .auth import decode_jwt
        decoded = decode_jwt(token)

        if decoded is None:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        # Since JWT is stateless, we can't "kill" the token.
        # We just tell client to forget it.
        return JsonResponse({'message': 'Logout successful. Please delete token on client side.'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

from .models import BlacklistedToken
@csrf_exempt
def logout_userr(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return JsonResponse({'error': 'Authorization header missing'}, status=401)

    try:
        token = auth_header.split(' ')[1]

        from .auth import decode_jwt
        decoded = decode_jwt(token)

        if decoded is None:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        user_id = decoded['user_id']
        user = User.objects.get(id=user_id, is_deleted=False)

        # ✅ Store token in blacklist table
        BlacklistedToken.objects.create(token=token, user=user)

        return JsonResponse({'message': 'Logout successful. Token blacklisted.'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def refresh_token(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))
        refresh_token = body.get('refresh_token')

        if not refresh_token:
            return JsonResponse({'error': 'Refresh token required'}, status=400)
        from .auth import decode_jwt, generate_jwt
        decoded = decode_jwt(refresh_token)
        if decoded is None:
            return JsonResponse({'error': 'Invalid or expired refresh token'}, status=401)

        user_id = decoded['user_id']
        access_token = generate_jwt(user_id, minutes=15)

        return JsonResponse({'access_token': access_token})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def delete_user(request):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'Only DELETE method allowed'}, status=405)

    # Get token from headers
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)

    token = auth_header.split(' ')[1]
    from .auth import decode_jwt
    decoded = decode_jwt(token)

    if not decoded:
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)

    try:
        user = User.objects.get(id=decoded['user_id'], is_deleted=False)
        user.is_deleted = True
        user.save()
        return JsonResponse({'message': 'User account deleted (soft delete)'}, status=200)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    

@csrf_exempt
def login_user_cook(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))
        email = body.get('email')
        password = body.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and Password required'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return JsonResponse({'error': 'Invalid email or password'}, status=401)
        from .auth import generate_jwt
        # Generate tokens
        access_token = generate_jwt(user.id, minutes=15)
        refresh_token = generate_jwt(user.id, days=7)

        response = JsonResponse({'message': 'Login successful'}, status=200)

        # Set tokens in HttpOnly cookies
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=15 * 60  # 15 minutes in seconds
        )
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=7 * 24 * 60 * 60  # 7 days in seconds
        )

        return response

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

@csrf_exempt
def refresh_token_cook(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        # Get refresh_token from cookie (not request body)
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return JsonResponse({'error': 'Refresh token not found in cookies'}, status=401)
        from .auth import decode_jwt, generate_jwt
        decoded = decode_jwt(refresh_token)
        if decoded is None:
            return JsonResponse({'error': 'Invalid or expired refresh token'}, status=401)

        user_id = decoded.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'Invalid token format'}, status=400)

        # Generate new access token
        access_token = generate_jwt(user_id, minutes=15)

        response = JsonResponse({'message': 'Token refreshed'})
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=15 * 60
        )

        return response

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
