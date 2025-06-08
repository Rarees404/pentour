from rest_framework import serializers
from django.contrib.auth import get_user_model

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

