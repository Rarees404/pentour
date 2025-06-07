from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Message

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Include public_key so it can be accepted on signup.
        fields = ["id", "username", "password", "public_key"]
        extra_kwargs = {
            "password": {"write_only": True},
            "public_key": {"required": False}  # public_key is optional during registration
        }

    def create(self, validated_data):
        # Remove public_key from validated_data so we can set it manually if provided.
        public_key = validated_data.pop("public_key", None)
        user = User(username=validated_data["username"])
        user.set_password(validated_data["password"])  # Hash the password
        if public_key:
            user.public_key = public_key
        user.save()
        return user


class MessageSerializer(serializers.ModelSerializer):
    sender_username = serializers.CharField(source='sender.username', read_only=True)
    is_current_user = serializers.SerializerMethodField()

    def get_is_current_user(self, obj):
        request = self.context.get('request')
        return obj.sender == request.user

    class Meta:
        model = Message
        fields = ['id', 'text', 'timestamp', 'sender_username', 'is_current_user']

