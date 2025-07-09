import random
from django.core.mail import EmailMultiAlternatives
from django.core.cache import cache
import requests
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from drf_yasg.utils import swagger_auto_schema
from user.serializers.auth_serializers import SignupSerializer, LoginSerializer, EmailCodeSerializer, VerifyCodeSerializer, GoogleIdTokenSerializer
from user.models import User
from django.utils.decorators import method_decorator
from django.conf import settings
from django.shortcuts import redirect
from django.views import View
from rest_framework.renderers import JSONRenderer
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import google.oauth2.id_token
import google.auth.transport.requests
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


# 회원가입
class SignupView(APIView):
    @swagger_auto_schema(request_body=SignupSerializer)
    def post(self, request):
        email = request.data.get('eml_adr')  # ✅ 필드명 수정!

        if not cache.get(email):
            return Response({"error": "이메일 인증이 필요합니다."}, status=400)
        
         # 2️⃣ 이미 가입된 회원 체크
        if User.objects.filter(eml_adr=email).exists():
            return Response({"error": "이미 가입된 회원입니다."},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "회원가입 성공"}, status=201)
        return Response(serializer.errors, status=400)


# 로그인
class LoginView(APIView):
    renderer_classes = [JSONRenderer]

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        email = request.data.get('eml_adr')  # ✅ 필드명 수정!
        password = request.data.get('password')
        user = authenticate(request, eml_adr=email, password=password)  # ✅ 키워드도 eml_adr로!

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
               'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'eml_adr': user.eml_adr,
                    'nm': user.nm,
                }
            })
        return Response({"error": "이메일 또는 비밀번호가 틀렸습니다."}, status=401)


# 이메일 인증 코드 전송

@swagger_auto_schema(method='post',request_body=EmailCodeSerializer)
@csrf_exempt
@api_view(['POST'])
def send_code(request):
    email = request.data.get('eml_adr')  # ✅ 필드명 수정
    code = str(random.randint(100000, 999999))
    cache.set(email, code, timeout=300)

    subject = "[나인위닛] 이메일 인증번호 안내"
    from_email = "9winit01@gmail.com"
    to_email = [email]

    text_content = f"인증번호는 {code} 입니다. 5분 이내에 입력해주세요."
    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>📩 나인위닛 이메일 인증</h2>
        <p>안녕하세요, <strong>나인위닛</strong>입니다.</p>
        <p>요청하신 인증번호는 다음과 같습니다:</p>
        <div style="font-size: 20px; font-weight: bold; background: #f2f2f2; padding: 10px; display: inline-block; border-radius: 5px;">
          🔐 {code}
        </div>
        <p style="margin-top: 20px;">본인이 요청하지 않은 경우 이 이메일은 무시하셔도 됩니다.</p>
        <p style="color: #888; font-size: 12px;">- 나인위닛</p>
      </body>
    </html>
    """

    msg = EmailMultiAlternatives(subject, text_content, from_email, to_email)
    msg.attach_alternative(html_content, "text/html")
    msg.send()

    return Response({'message': '코드 전송 완료'})


# 인증 코드 확인
@swagger_auto_schema(method='post',request_body=VerifyCodeSerializer)
@api_view(['POST'])
def verify_code(request):
    email = request.data.get('eml_adr')  # ✅ 필드명 수정
    code = request.data.get('code')
    saved = cache.get(email)

    if saved == code:
        return Response({'message': '인증 성공'})
    else:
        return Response({'message': '인증 실패'}, status=400)
    


    
@method_decorator(csrf_exempt, name="dispatch")  # POST지만 크로스 사이트 오지 않으므로 빼도 OK
class GoogleIdTokenVerifyView(APIView):
    permission_classes = [AllowAny]     # 로그인 전 접근 허용
    authentication_classes = []         # 세션·JWT 인증 스킵

    @swagger_auto_schema(
        request_body=GoogleIdTokenSerializer,
        responses={
            200: openapi.Response(
                description="로그인 성공",
                examples={
                    "application/json": {
                        "access": "jwt_access_token",
                        "refresh": "jwt_refresh_token",
                        "user": {
                            "eml_adr": "test@example.com",
                            "nm": "홍길동"
                        }
                    }
                }
            ),
            400: openapi.Response(
                description="잘못된 요청 or id_token 오류",
                examples={
                    "application/json": {"error": "id_token 누락"},
                },
            ),
        },
        operation_description="✅ 구글 ID 토큰을 검증하고 JWT를 발급합니다.",
        operation_summary="구글 로그인 검증 및 JWT 발급"
    )
    def post(self, request):
        id_token_str = request.data.get("id_token")
        if not id_token_str:
            return Response({"error": "id_token 누락"}, status=400)

        # 1. id_token 검증 (audience·exp 자동 체크)
        try:
            idinfo = google.oauth2.id_token.verify_oauth2_token(
                id_token_str,
                google.auth.transport.requests.Request(),
                settings.GOOGLE_CLIENT_ID,
            )
        except ValueError:
            return Response({"error": "유효하지 않은 id_token"}, status=400)

        # 2. 사용자 정보
        email = idinfo["email"]
        name  = idinfo.get("name", "")

        # 3. DB 저장 / 조회
        user, _ = User.objects.get_or_create(
            eml_adr=email,
            defaults={"nm": name}
        )

        # (옵션) 이름이 바뀐 경우 업데이트
        if user.nm != name:
            user.nm = name
            user.save()

        # 4. JWT 발급
        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {"eml_adr": user.eml_adr, "nm": user.nm},
            },
            status=200,
        )
