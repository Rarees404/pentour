from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "password"]
        extra_kwargs = {"password": {"write_only": True}}  # Hide password in API responses

    def create(self, validated_data):
        user = User(username=validated_data["username"])
        user.set_password(validated_data["password"])  #  Hash password
        user.save()
        return user
