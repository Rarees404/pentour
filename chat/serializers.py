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

# chat/serializers.py (example, adjust path as needed)
from rest_framework import serializers
from .models import Message, User # Assuming your User model is in .models

class MessageSerializer(serializers.ModelSerializer):
    # Add a field to indicate if the message was sent by the current user
    is_current_user = serializers.SerializerMethodField()
    sender_username = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            'id',
            'sender',
            'receiver',
            'encrypted_text',
            'encrypted_symmetric_key', # <-- Make sure this is included
            'aes_nonce',               # <-- Make sure this is included
            'aes_tag',                 # <-- Make sure this is included
            'signature',
            'timestamp',
            'is_current_user',
            'sender_username',
        ]

    def get_is_current_user(self, obj):
        # This assumes 'request' is available in the serializer context
        request = self.context.get('request')
        if request and request.user == obj.sender:
            return True
        return False

    def get_sender_username(self, obj):
        return obj.sender.username
