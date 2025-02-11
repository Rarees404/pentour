from django.db import models

# Create your models here.

from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import uuid

# Custom User Model (Stores Public Key)

class User(AbstractUser):
    public_key = models.TextField(null=True, blank=True)  # Stores user's RSA public key

    # Avoid conflicts with Django's built-in User model
    groups = models.ManyToManyField(Group, related_name="chat_users", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="chat_user_permissions", blank=True)

# Stores Encrypted Messages
class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    encrypted_text = models.TextField()  # Stores AES-256 encrypted message
    timestamp = models.DateTimeField(auto_now_add=True)

