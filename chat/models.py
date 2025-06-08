# Create your models here.

from django.contrib.auth.models import AbstractUser, Group, Permission
import uuid
from django.conf import settings
from django.db import models
# Custom User Model (Stores Public Key)

class User(AbstractUser):
    # Store the user's TOTP secret
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    # Flag to require 2FA at login
    is_2fa_enabled = models.BooleanField(default=False)


    public_key = models.TextField(null=True, blank=True)
    private_kyte = models.TextField(null=True, blank=True)# Stores user's RSA public key

    # Avoid conflicts with Django's built-in User model
    groups = models.ManyToManyField(Group, related_name="chat_users", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="chat_user_permissions", blank=True)


# Stores Encrypted Messages
class Message(models.Model):

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sent_messages",
        db_index=True,
    )
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="received_messages",
        db_index=True,
    )
    encrypted_text = models.TextField()  # Stores AES-256 encrypted message
    encrypted_symmetric_key = models.TextField(null=True, blank=True)
    aes_nonce = models.TextField(null=True, blank=True)
    aes_tag = models.TextField(null=True, blank=True)
    signature = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        indexes = [
            models.Index(
                fields=['receiver', '-timestamp'],
                name='msg_recv_time_idx'
            ),
        ]

    def __str__(self):
        return f"From {self.sender} to {self.receiver} at {self.timestamp}"
