# Generated by Django 5.2.4 on 2025-07-12 21:45

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_socialaccount'),
    ]

    operations = [
        migrations.AlterField(
            model_name='socialaccount',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='social_accounts', to=settings.AUTH_USER_MODEL),
        ),
    ]
