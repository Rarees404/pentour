# chat/models.py
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import uuid
from django.conf import settings

class User(AbstractUser):
    # Store the user's TOTP secret (if you’re still using 2FA)
    totp_secret   = models.CharField(max_length=32, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)

    # Only store the PEM‐encoded public key; no private key on server
    public_key= models.TextField(null=True, blank=True)
    # PEM of the RSA-PSS public key (for verifying signatures)
    signing_public_key = models.TextField(null=True, blank=True)


class Chat(models.Model):
    pin = models.CharField(max_length=4, unique=True, db_index=True)
    user1 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="chats_as_user1",
        null=True,
        blank=True
    )
    user2 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="chats_as_user2",
        null=True,
        blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Chat {self.pin}"

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
    # AES‐GCM ciphertext (base64‐encoded by client, stored as text here)
    encrypted_text = models.TextField()

    # The AES key wrapped with RSA (base64‐encoded by client, stored as text)
    encrypted_symmetric_key = models.TextField(null=True, blank=True)

    # AES‐GCM nonce (base64) and tag (base64), also stored as text
    aes_nonce = models.TextField(null=True, blank=True)
    aes_tag   = models.TextField(null=True, blank=True)

    # RSA signature (base64‐encoded) of the ciphertext (or ciphertext+nonce)
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
