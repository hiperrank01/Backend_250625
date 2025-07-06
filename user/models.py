from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('이메일은 필수입니다')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # 비밀번호 암호화
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=30)
    role = models.CharField(max_length=20, choices=[('admin', '관리자'), ('agency', '대행사'), ('advertiser', '광고주')])
    joined_at = models.DateTimeField(auto_now_add=True)
    is_paying = models.BooleanField(default=False)
    api_key = models.CharField(max_length=100, blank=True, null=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email' # 로그인 시 사용할 필드
    REQUIRED_FIELDS = ['username'] # createsuperuser 명령어 시 추가로 입력받을 필드들

    objects = UserManager()