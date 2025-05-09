from django.contrib.auth import authenticate, get_user_model
from django.utils.timezone import now
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.contrib.auth import authenticate, login as django_login
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import pyotp
from django.db.models import Q
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from .models import Message
from rest_framework.generics import CreateAPIView
from .serializers import UserSerializer
from .models import Message
from threading import Lock
import time
import sys
import os
import uuid
import logging
import pyotp
import qrcode
import io
import base64
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
logger = logging.getLogger(__name__)




# In-memory storage for matchmaking; in production, consider a persistent solution.
#queue = []        # Stores waiting users for chat sessions
#active_chats = {} # Maps chat IDs to a tuple of user objects (user1, user2)
#queue_lock = Lock()
sent_messages_cache = {}  # {msg.id: plaintext}



# Home Page View - renders index.html
def home(request):
    return render(request, "index.html")

# Authentication Page View (Login/Register UI) - renders auth.html
def auth_page(request):
    return render(request, "auth.html")


def user_menu(request):
    return render(request, "usermenu.html")


# Chatbox Page View - renders chatbox.html
def chat_box(request):
    return render(request, "chatbox.html")

active_chats = {}



# User Registration View
# Explicitly use the custom User model (chat_user)
User = get_user_model()

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class RegisterUserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        logger.info(f"[REGISTER] New registration request for username: {username}")
        if User.objects.filter(username=username).exists():
            return Response({"message": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate RSA Key Pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        logger.debug(f"[REGISTER] RSA key pair generated for user: {username}")

        # Serialize public key to store in DB
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Serialize private key to store on disk
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Create user with public key
        user = User(username=username, public_key=public_pem)
        user.set_password(password)
        user.save()
        logger.info(f"[REGISTER] User created and public key saved for: {username}")

        # Save private key to a file
        key_dir = os.path.join("chat", "client", "enc_test_keygen", "static", "keys")
        os.makedirs(key_dir, exist_ok=True)
        key_path = os.path.join(key_dir, f"{username}_private_key.pem")
        with open(key_path, "wb") as f:
            f.write(private_pem)

        logger.info(f"[REGISTER] Private key saved at: {os.path.join(key_dir, f'{username}_private_key.pem')}")
        return Response({"message": "Registration successful!"}, status=status.HTTP_201_CREATED)


# User Login View
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        otp_code = request.data.get('otp_code')  # optional, if 2FA enabled

        user = authenticate(username=username, password=password)
        if not user:
            return Response(
                {'detail': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # ← NEW: create a Django session so request.user is set later
        django_login(request, user)

        # If the user has 2FA enabled, verify the OTP code
        if user.is_2fa_enabled:
            totp = pyotp.TOTP(user.totp_secret)
            if not otp_code or not totp.verify(otp_code):
                return Response(
                    {'detail': 'Invalid or missing 2FA code'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # Issue (or retrieve) the DRF Token
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})


class UserMenuView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "username": user.username,
            "email": user.email,
            "menu": [
                {"label": "Start Chat", "path": "/chat/start/"},
                {"label": "Join Chat", "path": "/chat/join/"},
                {"label": "Logout", "path": "/logout/"}
            ]
        })


class CreateChatView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        chat_id = str(uuid.uuid4())  # generate unique ID
        active_chats[chat_id] = [request.user]  # store creator
        return Response({"chat_id": chat_id}, status=status.HTTP_201_CREATED)


class JoinChatView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        chat_id = request.data.get("chat_id")
        if not chat_id:
            return Response({"message": "Chat ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        if chat_id not in active_chats:
            return Response({"message": "Chat not found"}, status=status.HTTP_404_NOT_FOUND)

        users = active_chats[chat_id]

        if request.user in users:
            return Response({"message": "You are already in this chat"}, status=status.HTTP_200_OK)

        if len(users) >= 2:
            return Response({"message": "Chat is full"}, status=status.HTTP_403_FORBIDDEN)

        users.append(request.user)
        partner = users[0]
        return Response({
            "message": "Successfully joined chat",
            "chat_id": chat_id,
            "partner": partner.username
        }, status=status.HTTP_200_OK)


# Check Active Chat View
class CheckChatView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        for chat_id, (user1, user2) in active_chats.items():
            if user in (user1, user2):
                if user == user1:
                    partner = user2.username
                else:
                    partner = user1.username
                return Response({
                    "chat_id": chat_id,
                    "partner": partner
                }, status=status.HTTP_200_OK)
        return Response({"message": "No active chat found."}, status=status.HTTP_404_NOT_FOUND)


# Leave Chat View - deletes the chat session and clears the message history
class LeaveChatView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        chat_to_remove = None

        for chat_id, (user1, user2) in active_chats.items():
            if user in (user1, user2):
                chat_to_remove = chat_id
                break

        if chat_to_remove:
            user1, user2 = active_chats[chat_to_remove]
            del active_chats[chat_to_remove]
            # Delete all messages exchanged between these two users
            Message.objects.filter(
                Q(sender=user1, receiver=user2) | Q(sender=user2, receiver=user1)
            ).delete()
            return Response({"message": "You left the chat. Chat history cleared."}, status=status.HTTP_200_OK)

        return Response({"message": "No active chat to leave."}, status=status.HTTP_400_BAD_REQUEST)


# Send Message View - saves a message in the database
from chat.client.enc_test_keygen.RSAEncryptor import (
    generate_aes_key, encrypt_with_aes, encrypt_aes_key_with_rsa, sign_message, verify_signature
)


class SendMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            logger.info("[SEND] Starting send flow for user '%s'", request.user.username)
            message_text = request.data.get("message")
            chat_id = request.data.get("chat_id")

            logger.debug("[SEND] message_text='%s', chat_id='%s'", message_text, chat_id)
            if chat_id not in active_chats:
                logger.warning("[SEND] Invalid chat_id '%s'", chat_id)
                return Response({"message": "Invalid chat ID."},
                                status=status.HTTP_400_BAD_REQUEST)

            user1, user2 = active_chats[chat_id]
            if request.user not in (user1, user2):
                logger.warning("[SEND] User '%s' not participant in chat '%s'", request.user.username, chat_id)
                return Response({"message": "Not a participant."},
                                status=status.HTTP_403_FORBIDDEN)

            receiver = user2 if request.user == user1 else user1
            logger.info("[SEND] Encrypting message for receiver '%s'", receiver.username)

            # 1) Generate AES key
            aes_key = generate_aes_key()
            logger.debug("[SEND] Generated AES key (32 bytes)")

            # 2) AES-encrypt the message
            encrypted = encrypt_with_aes(aes_key, message_text)
            logger.debug(
                "[SEND] AES encryption complete: ciphertext_len=%d, nonce=%s, tag=%s",
                len(encrypted["ciphertext"]), encrypted["nonce"], encrypted["tag"]
            )

            # 3) RSA-encrypt the AES key
            public_pem = receiver.public_key
            encrypted_key = encrypt_aes_key_with_rsa(public_pem, aes_key)
            logger.debug(
                "[SEND] RSA encryption of AES key complete: encrypted_key_len=%d",
                len(encrypted_key)
            )

            # 4) Sign the plaintext message
            priv_path = f"chat/client/enc_test_keygen/static/keys/{request.user.username}_private_key.pem"
            with open(priv_path, "r") as f:
                priv_pem = f.read()
            signature = sign_message(priv_pem, message_text)
            logger.debug("[SEND] Signature generated: signature_len=%d", len(signature))

            # 5) Store in DB
            msg = Message.objects.create(
                sender=request.user,
                receiver=receiver,
                encrypted_text=encrypted["ciphertext"],
                encrypted_symmetric_key=encrypted_key,
                aes_nonce=encrypted["nonce"],
                aes_tag=encrypted["tag"],
                signature=signature
            )
            sent_messages_cache[msg.id] = message_text
            logger.info("[SEND] Stored Message(id=%d) with signature", msg.id)

            return Response({"message": "Message sent."}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("[SEND] ERROR: %s", str(e), exc_info=True)
            return Response({"error": str(e)}, status=500)


from chat.client.enc_test_keygen.RSAEncryptor import (
    decrypt_with_aes, decrypt_aes_key_with_rsa
)


class GetMessagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        logger.info("[GET] Retrieving messages for chat '%s' and user '%s'", chat_id, request.user.username)

        if chat_id not in active_chats:
            logger.warning("[GET] Chat '%s' not found", chat_id)
            return Response({"error": "Chat not found"}, status=status.HTTP_404_NOT_FOUND)

        user1, user2 = active_chats[chat_id]
        if request.user not in (user1, user2):
            logger.warning("[GET] User '%s' not participant in chat '%s'", request.user.username, chat_id)
            return Response({"error": "Not a participant"}, status=status.HTTP_403_FORBIDDEN)

        msgs = Message.objects.filter(
            Q(sender=user1, receiver=user2) | Q(sender=user2, receiver=user1)
        ).order_by("timestamp")

        # Load private key
        priv_path = f"chat/client/enc_test_keygen/static/keys/{request.user.username}_private_key.pem"
        with open(priv_path, "r") as f:
            private_pem = f.read()
        logger.debug("[GET] Loaded private key for '%s'", request.user.username)

        out = []
        for m in msgs:
            logger.debug("[GET] Processing Message(id=%d)", m.id)
            if m.receiver == request.user:
                try:
                    # RSA-decrypt AES key
                    logger.debug("[GET] RSA-decrypting AES key for Message(id=%d)", m.id)
                    aes_key = decrypt_aes_key_with_rsa(private_pem, m.encrypted_symmetric_key)
                    logger.debug("[GET] AES key decrypted for Message(id=%d)", m.id)

                    # AES-decrypt message
                    logger.debug("[GET] AES-decrypting ciphertext for Message(id=%d)", m.id)
                    plaintext = decrypt_with_aes(aes_key, {
                        "ciphertext": m.encrypted_text,
                        "nonce": m.aes_nonce,
                        "tag": m.aes_tag
                    })
                    logger.debug("[GET] AES decryption complete, plaintext_len=%d", len(plaintext))

                    # Verify signature
                    logger.debug("[GET] Verifying signature for Message(id=%d)", m.id)
                    if verify_signature(m.sender.public_key, plaintext, m.signature):
                        logger.debug("[GET] Signature valid for Message(id=%d)", m.id)
                    else:
                        logger.warning("[GET] Signature INVALID for Message(id=%d) — possible tampering", m.id)
                        plaintext = "[Tampered] " + plaintext

                except Exception as e:
                    logger.error("[GET] Decryption/Verification failed for Message(id=%d): %s", m.id, e)
                    plaintext = "[Decryption failed]"

            else:
                plaintext = sent_messages_cache.get(m.id, "[Sent]")

            out.append({
                "id": m.id,
                "sender_id": m.sender.id,
                "sender_username": m.sender.username,
                "text": plaintext,
                "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "is_current_user": (m.sender == request.user)
            })

        partner = user2.username if request.user == user1 else user1.username
        logger.info("[GET] Retrieved %d messages for chat '%s'", len(out), chat_id)
        return Response({
            "current_user": request.user.username,
            "partner": partner,
            "messages": out
        })

@login_required
def setup_2fa(request):
    user = request.user

    # 1) On first visit, generate & store a new secret
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    # 2) Build the URI for Google Authenticator
    totp = pyotp.TOTP(user.totp_secret)
    otp_uri = totp.provisioning_uri(name=user.username, issuer_name='Secure Chat')

    # 3) Render a QR code image as base64
    qr_img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    qr_data = base64.b64encode(buffer.getvalue()).decode()

    # 4) If the form was submitted, verify the user’s code
    if request.method == 'POST':
        code = request.POST.get('otp_code')
        if totp.verify(code):
            user.is_2fa_enabled = True
            user.save()
            messages.success(request, '2FA activated successfully.')
            return redirect('user_menu')
        else:
            messages.error(request, 'Invalid code, please try again.')

    return render(request, 'chat/2fa_setup.html', {
        'qr_data': qr_data,
    })
