from django.contrib import admin
from django.urls import path, include
from django.urls import path, re_path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Backend 250625 API",
        default_version='v1',
    ),
    public=True,
    url="https://api.ninewinit.store",  # 🔥 여기 추가!
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # user 앱 전체 연결
    path('user/', include('user.urls')),  # user/urls.py로 연결되게

     re_path(r'^swagger(?P<format>\.json|\.yaml)$',
            schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0),
         name='schema-redoc'),
]
