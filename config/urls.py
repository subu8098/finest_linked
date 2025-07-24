from django.contrib import admin
from django.urls import path, include  # include is needed to connect sub-routes

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/', include('user.urls')),  
    path('post/', include('post.urls')),
    
]
from django.conf import settings
from django.conf.urls.static import static

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

