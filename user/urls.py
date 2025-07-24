from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user),  # This maps /user/register to your view
    path('login/', views.login_user),
    path('profile/',views.user_profile),
    path('profile/update/', views.update_user_profile),  # PUT
    path('logout/', views.logout_user),
    path('logoutt/', views.logout_userr),  # DELETE
    path('loginn/', views.login_userr),
    path('refresh/', views.refresh_token),  # For refreshing tokens
    path('delete/', views.delete_user),
    path('login_cookie/', views.login_user_cook),  # For login with cookies
    path('refresh_cookie/', views.refresh_token_cook),  # For refreshing tokens with cookies

]
