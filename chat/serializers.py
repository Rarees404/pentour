# chat/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Message

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "public_key",
            "is_2fa_enabled",
            "totp_secret",
        ]
        read_only_fields = ["is_2fa_enabled", "totp_secret", "id"]

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = [
            "id",
            "sender",
            "receiver",
            "encrypted_text",
            "encrypted_symmetric_key",
            "aes_nonce",
            "aes_tag",
            "signature",
            "timestamp",
        ]
        read_only_fields = ["id", "timestamp", "sender"]
