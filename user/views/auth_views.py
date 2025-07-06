import random
from django.core.mail import EmailMultiAlternatives
from django.core.cache import cache
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt

from user.serializers.auth_serializers import AuthSerializer
from user.models import User


# 회원가입
class SignupView(APIView):
    def post(self, request):
        email = request.data.get('eml_adr')  # ✅ 필드명 수정!

        if not cache.get(email):
            return Response({"error": "이메일 인증이 필요합니다."}, status=400)

        serializer = AuthSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "회원가입 성공"}, status=201)
        return Response(serializer.errors, status=400)


# 로그인
class LoginView(APIView):
    def post(self, request):
        email = request.data.get('eml_adr')  # ✅ 필드명 수정!
        password = request.data.get('password')
        user = authenticate(request, eml_adr=email, password=password)  # ✅ 키워드도 eml_adr로!

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'nm': user.nm,
                'mbr_no': user.mbr_no,
            })
        return Response({"error": "이메일 또는 비밀번호가 틀렸습니다."}, status=401)


# 이메일 인증 코드 전송
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
@api_view(['POST'])
def verify_code(request):
    email = request.data.get('eml_adr')  # ✅ 필드명 수정
    code = request.data.get('code')
    saved = cache.get(email)

    if saved == code:
        return Response({'message': '인증 성공'})
    else:
        return Response({'message': '인증 실패'}, status=400)