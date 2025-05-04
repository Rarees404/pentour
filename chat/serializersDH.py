from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Include public_key and ecdh_signature so they can be accepted on signup.
        fields = ["id", "username", "password", "public_key", "ecdh_signature"]
        extra_kwargs = {
            "password": {"write_only": True},
            "public_key": {"required": False},  # public_key is optional during registration
            "ecdh_signature": {"required": False},  # ecdh_signature is optional during registration
        }

    def create(self, validated_data):
        # Remove public_key and ecdh_signature from validated_data so we can set them manually if provided.
        public_key = validated_data.pop("public_key", None)
        ecdh_signature = validated_data.pop("ecdh_signature", None)
        user = User(username=validated_data["username"])
        user.set_password(validated_data["password"])  # Hash the password
        if public_key:
            user.public_key = public_key
        if ecdh_signature:
            user.ecdh_signature = ecdh_signature
        user.save()
        return user
