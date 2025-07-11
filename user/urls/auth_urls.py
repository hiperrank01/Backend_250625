from django.urls import path
from user.views.auth_views import SignupView, LoginView, send_code, verify_code, GoogleIdTokenVerifyView, NaverVerifyView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('send-code/', send_code, name='send_code'),       # ✅ 함수형 뷰는 그대로!
    path('verify-code/', verify_code, name='verify_code'), # ✅
    path("google/verify/", GoogleIdTokenVerifyView.as_view(), name='google_callback'),
    path("naver/verify/", NaverVerifyView.as_view(), name='naver_callback'),
]