from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from django.http import JsonResponse
from user.models import User
from .models import Post
from user.auth import decode_jwt
from cloudinary_config import cloudinary
import cloudinary.uploader


@csrf_exempt
def create_post(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)

    # Get token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Missing or invalid token'}, status=401)

    token = auth_header.split(' ')[1]
    payload = decode_jwt(token)
    if not payload:
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)

    user_id = payload['user_id']
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # Get form-data
    content = request.POST.get('content')
    visibility = request.POST.get('visibility', 'public')
    image = request.FILES.get('image')  # 👈 File comes here

    if not content:
        return JsonResponse({'error': 'Content is required'}, status=400)

    if visibility not in ['public', 'connections', 'private']:
        return JsonResponse({'error': 'Invalid visibility value'}, status=400)
    
    image_url= None
    if image:
        uploaded = cloudinary.uploader.upload(image, folder='linkedin_clone/posts')
        image_url = uploaded.get('secure_url')

    # Create Post
    post = Post.objects.create(
        user=user,
        content=content,
        visibility=visibility,
        image_url=image_url
    )

    return JsonResponse({
        'message1':f"Post created successfully by {user.name}",
        'message': 'Post created successfully',
        'post_id': post.id,
        'image_url': request.build_absolute_uri(post.image_url) if post.image_url   else None

    }, status=201)

@csrf_exempt
@require_GET
def post_feed(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Missing or invalid token'}, status=401)

    token = auth_header.split(' ')[1]
    payload = decode_jwt(token)
    if not payload:
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)

    user_id = payload['user_id']
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    posts = Post.objects.filter(is_deleted=False).order_by('-created_at')
    post_list = []

    for post in posts:
        post_data = {
            'post_id': post.id,
            'user_name': post.user.name,
            'content': post.content,
            'visibility': post.visibility,
            'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'image_url': request.build_absolute_uri(post.image_url) if post.image_url else None,
        }
        post_list.append(post_data)

    return JsonResponse({'posts': post_list}, status=200)
    
@csrf_exempt
def update_post(request, post_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)

    # 1. Authorization Token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Missing or invalid token'}, status=401)

    token = auth_header.split(' ')[1]
    payload = decode_jwt(token)
    if not payload:
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)

    user_id = payload['user_id']
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # 2. Get Post
    try:
        post = Post.objects.get(id=post_id, user=user, is_deleted=False)
    except Post.DoesNotExist:
        return JsonResponse({'error': 'Post not found'}, status=404)

    # 3. Get form data
    content = request.POST.get('content')
    visibility = request.POST.get('visibility', 'public')
    image = request.FILES.get('image')

    if not content:
        return JsonResponse({'error': 'Content is required'}, status=400)

    if visibility not in ['public', 'connections', 'private']:
        return JsonResponse({'error': 'Invalid visibility value'}, status=400)

    # 4. Upload new image if provided
    if image:
        uploaded = cloudinary.uploader.upload(image, folder='linkedin_clone/posts')
        image_url = uploaded.get('secure_url')
        post.image_url = image_url  # update image_url

    # 5. Save updates
    post.content = content
    post.visibility = visibility
    post.save()

    return JsonResponse({
        'message': 'Post updated successfully',
        'post_id': post.id,
        'image_url': request.build_absolute_uri(post.image_url) if post.image_url else None
    }, status=200)

@csrf_exempt
def delete_post(request, post_id):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'Only DELETE allowed'}, status=405)

    access_token=request.COOKIES.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'Missing or invalid token'}, status=401)
    payload = decode_jwt(access_token)
    if not payload:
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    user_id=payload['user_id']
    user=User.objects.get(id=user_id)
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # 2. Get Post
    try:
        post = Post.objects.get(id=post_id, user=user, is_deleted=False)
    except Post.DoesNotExist:
        return JsonResponse({'error': 'Post not found'}, status=404)
    
    post.is_deleted=True
    post.save()

    return JsonResponse({'error':'Deleted succesfully'},status=200)
    
@csrf_exempt
def like_post(request, post_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)
    access_token = request.COOKIES.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'Missing or invalid token'}, status=401)
    payload = decode_jwt(access_token)
    if not payload:
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    post=Post.objects.get(id=post_id)
    user=User.objects.get(id=payload['user_id'])
    if not post:
        return JsonResponse({'error': 'Post not found'}, status=404)
    if not user:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    like, created = Like.objects.get_or_create(user=user, post=post)
    if not created:
        like.delete()
        return JsonResponse({'message': 'Post unliked successfully'}, status=200)
    return JsonResponse({'message': 'Post liked successfully'}, status=201)

    