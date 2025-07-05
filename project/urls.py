from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # user 앱 전체 연결
    path('user/', include('user.urls')),  # user/urls.py로 연결되게
]
