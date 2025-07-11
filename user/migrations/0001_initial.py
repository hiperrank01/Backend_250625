# Generated by Django 5.1.7 on 2025-07-06 20:26

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('mbr_no', models.CharField(max_length=18, primary_key=True, serialize=False, verbose_name='회번호')),
                ('eml_adr', models.EmailField(max_length=100, unique=True, verbose_name='이메일주소')),
                ('pwd', models.CharField(max_length=256, verbose_name='비밀번호')),
                ('nm', models.CharField(max_length=20, verbose_name='이름')),
                ('phn_no', models.CharField(max_length=20, verbose_name='전화번호')),
                ('rcm_eml', models.EmailField(blank=True, max_length=100, null=True, verbose_name='추천인이메일')),
                ('prv_agr_yn', models.CharField(max_length=1, verbose_name='개인정보동의여부')),
                ('tos_agr_yn', models.CharField(max_length=1, verbose_name='이용약관동의여부')),
                ('adv_rcv_yn', models.CharField(max_length=1, verbose_name='광고수신동의여부')),
                ('reg_dtm', models.DateTimeField(auto_now_add=True, verbose_name='등록일시')),
                ('reg_usr_eml_adr', models.EmailField(max_length=100, verbose_name='등록자이메일주소')),
                ('upd_dtm', models.DateTimeField(auto_now=True, verbose_name='수정일시')),
                ('upd_usr_eml_adr', models.EmailField(max_length=100, verbose_name='수정자이메일주소')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': '회원기본',
                'verbose_name_plural': '회원기본',
                'db_table': 'user',
            },
        ),
    ]
