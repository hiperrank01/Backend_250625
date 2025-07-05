from django.urls import path, include

urlpatterns = [
    path('auth/', include('user.urls.auth_urls')),
]