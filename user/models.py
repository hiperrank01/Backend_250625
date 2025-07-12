from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid

class UserManager(BaseUserManager):
    def create_user(self, eml_adr, password=None, **extra_fields):
        if not eml_adr:
            raise ValueError('이메일은 필수입니다')
        eml_adr = self.normalize_email(eml_adr)
        
        if 'mbr_no' not in extra_fields:
            extra_fields['mbr_no'] = str(uuid.uuid4().hex[:18])  # 고유 18자리

        user = self.model(eml_adr=eml_adr, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, eml_adr, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(eml_adr, password, **extra_fields)
    
     

class User(AbstractBaseUser, PermissionsMixin):
    mbr_no = models.CharField("회번호", max_length=18, primary_key=True)

    eml_adr = models.EmailField("이메일주소", max_length=100, unique=True)
    pwd = models.CharField("비밀번호", max_length=256)
    nm = models.CharField("이름", max_length=20)
    phn_no = models.CharField("전화번호", max_length=20)
    rcm_eml = models.EmailField("추천인이메일", max_length=100, null=True, blank=True)

    prv_agr_yn = models.CharField("개인정보동의여부", max_length=1)
    tos_agr_yn = models.CharField("이용약관동의여부", max_length=1)
    adv_rcv_yn = models.CharField("광고수신동의여부", max_length=1)

    reg_dtm = models.DateTimeField("등록일시", auto_now_add=True)
    reg_usr_eml_adr = models.EmailField("등록자이메일주소", max_length=100)
    upd_dtm = models.DateTimeField("수정일시", auto_now=True)
    upd_usr_eml_adr = models.EmailField("수정자이메일주소", max_length=100)

    class Meta:
        db_table = 'user'
        verbose_name = '회원기본'
        verbose_name_plural = '회원기본'
    
    def __str__(self):
        return f"{self.nm} ({self.eml_adr})"
    

    USERNAME_FIELD = 'eml_adr'  # 로그인에 사용할 필드
    REQUIRED_FIELDS = ['nm', 'phn_no']  # createsuperuser 때 추가 입력받을 필드
    
    objects = UserManager()


class SocialAccount(models.Model):
    PROVIDER_CHOICES = [
        ("naver",  "Naver"),
        ("google", "Google"),
        ("kakao",  "Kakao"),
        ("apple",  "Apple"),
    ]

    user     = models.ForeignKey(
        User, related_name="social_accounts",
        on_delete=models.CASCADE,
        null=True,      # ✅
        blank=True,     # ✅
    )
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    uid      = models.CharField(max_length=100)           # 네이버 id, 구글 sub 등
    email    = models.EmailField(null=True, blank=True)
    extra    = models.JSONField(null=True, blank=True)    # 프로필 raw 저장

    class Meta:
        unique_together = ("provider", "uid")             # 동일 계정 중복 방지

    def __str__(self):
        return f"{self.provider}:{self.uid} → {self.user.eml_adr}"