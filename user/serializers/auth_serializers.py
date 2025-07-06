from rest_framework import serializers
from user.models import User
import uuid

class AuthSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'eml_adr',
            'password',
            'nm',
            'phn_no',
            'rcm_eml',
            'prv_agr_yn',
            'tos_agr_yn',
            'adv_rcv_yn',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        # mbr_no 자동 생성
        validated_data['mbr_no'] = uuid.uuid4().hex[:18]
        # reg_usr_eml_adr, upd_usr_eml_adr도 기본값 채우기
        validated_data['reg_usr_eml_adr'] = validated_data['eml_adr']
        validated_data['upd_usr_eml_adr'] = validated_data['eml_adr']

        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user