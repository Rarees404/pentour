# chat/serializers.py
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Message, User
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
    sender_public_key = serializers.CharField(source="sender.public_key",         read_only=True)
    sender_signing_public_key = serializers.CharField(source="sender.signing_public_key", read_only=True)

    class Meta:
        model  = Message
        fields = [
            "id",
            "encrypted_text",
            "encrypted_symmetric_key",
            "aes_nonce",
            "aes_tag",
            "signature",
            "timestamp",
            "sender_public_key",
            "sender_signing_public_key",
        ]

    def get_is_current_user(self, obj):
        # This assumes 'request' is available in the serializer context
        request = self.context.get('request')
        if request and request.user == obj.sender:
            return True
        return False

    def get_sender_username(self, obj):
        return obj.sender.username
