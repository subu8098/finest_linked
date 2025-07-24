from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.create_post),
    path('feed/', views.post_feed),  # Assuming you have a view for getting the feed
    path('update/<int:post_id>/', views.update_post),
    path('delete/<int:post_id>/', views.delete_post),
    path('like/<int:post_id>/', views.like_post),
]
