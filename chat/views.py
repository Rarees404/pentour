from django.contrib.auth import authenticate, get_user_model
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
from rest_framework.generics import CreateAPIView
from .serializers import UserSerializer, MessageSerializer
from .models import Message
from threading import Lock
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
from collections import defaultdict
import time
import re
import random
from rest_framework.authentication import TokenAuthentication
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import Chat


# Track failed login attempts per IP: {ip: (last_attempt_time, wait_time)}
failed_login_ips = defaultdict(lambda: {'last_time': 0, 'wait_time': 0, 'fail_count': 0})


# In-memory storage for matchmaking; in production, consider a persistent solution.
#queue = []        # Stores waiting users for chat sessions
#active_chats = {} # Maps chat IDs to a tuple of user objects (user1, user2)
#queue_lock = Lock()
sent_messages_cache = {}  # {msg.id: plaintext}



# Home Page View - renders index.html
def home(request):
    return render(request, "index.html")

# Authentication Page View (Login/Register UI) - renders auth.html
@ensure_csrf_cookie
def auth_page(request):
    return render(request, "auth.html")


def user_menu(request):
    return render(request, "usermenu.html")


# Chatbox Page View - renders chatbox.html
def chatbox(request):
    username = request.user.username
    chat_id = request.session.get("chat_id")

    try:
        chat = Chat.objects.get(pin=chat_id)
    except Chat.DoesNotExist:
        return redirect("/chat/usermenu/")
    participants = [chat.user1.username if chat.user1 else None,
                    chat.user2.username if chat.user2 else None]

    context = {
        "chat_id": chat_id,
        "username": username,
        "participants": participants,
    }
    return render(request, "chatbox.html", context)

active_chats = {}



# User Registration View
# Explicitly use the custom User model (chat_user)
User = get_user_model()

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



class RegisterUserView(CreateAPIView):
    """
    Registration now *requires* the client to send their public_key PEM.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        public_key = request.data.get("public_key")

        # Basic input validation
        if not username or not is_valid_username(username):
            return Response(
                {"message": "Username contains invalid characters."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not password:
            return Response(
                {"message": "Password cannot be empty."}, status=status.HTTP_400_BAD_REQUEST
            )
        if not public_key:
            return Response(
                {"message": "Public key is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Very basic PEM‐format validation
        if not public_key.startswith("-----BEGIN PUBLIC KEY-----") or not public_key.endswith(
                "-----END PUBLIC KEY-----"
        ):
            return Response(
                {"message": "Invalid public key format."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Attempt to load it to confirm it's a valid PEM
            from cryptography.hazmat.primitives import serialization

            serialization.load_pem_public_key(public_key.encode())
        except Exception as e:
            logger.warning(f"[REGISTER] Invalid public key provided: {e}")
            return Response(
                {"message": "Invalid public key."}, status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"[REGISTER] New registration request for username: {username}")
        if User.objects.filter(username=username).exists():
            return Response(
                {"message": "Username already exists."}, status=status.HTTP_400_BAD_REQUEST
            )

        user = User(username=username, public_key=public_key)
        user.set_password(password)
        user.save()
        logger.info(f"[REGISTER] User created with client‐provided public key: {username}")

        return Response({"message": "Registration successful!"}, status=status.HTTP_201_CREATED)


def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

from rest_framework.authentication import SessionAuthentication, BasicAuthentication
class LoginView(APIView):
    """
    Expects JSON body: { "username": "...", "password": "...", "otp_code": "..." (optional) }
    On success, calls django_login() → sets sessionid cookie, and returns a DRF token for future AJAX calls.
    """
    authentication_classes = [SessionAuthentication]
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        otp_code = request.data.get("otp_code", None)

        if not username or not password:
            return Response(
                {"message": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"[LOGIN] Attempt login for '{username}' from IP {request.META.get('REMOTE_ADDR')}")
        user = authenticate(username=username, password=password)
        if not user:
            logger.warning(f"[LOGIN] Invalid credentials for '{username}'.")
            return Response({"message": "Invalid username or password."}, status=status.HTTP_401_UNAUTHORIZED)

        # (If you have 2FA logic, handle otp_code here.
        # For brevity, we're assuming no 2FA in this snippet.)

        # Create a Django session
        django_login(request, user)

        # Issue (or retrieve) the DRF token
        token, _ = Token.objects.get_or_create(user=user)
        logger.info(f"[LOGIN] User '{username}' authenticated successfully.")
        return Response(
            {
                "token": token.key,
                "public_key_exists": bool(user.public_key),
            },
            status=status.HTTP_200_OK,
        )


class UploadPublicKeyView(APIView):
    """
    When a user logs in and doesn't have a public key yet, the JS will call this endpoint
    (with sessionid cookie) to upload the newly‐generated public key PEM.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        public_key = request.data.get("public_key", None)
        if not public_key:
            return Response(
                {"message": "Public key is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Very basic PEM‐format validation
        if not public_key.startswith("-----BEGIN PUBLIC KEY-----") or not public_key.endswith(
                "-----END PUBLIC KEY-----"
        ):
            return Response(
                {"message": "Invalid public key format."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from cryptography.hazmat.primitives import serialization

            serialization.load_pem_public_key(public_key.encode())
        except Exception as e:
            logger.warning(f"[UPLOAD-KEY] Invalid public key provided by '{request.user.username}': {e}")
            return Response(
                {"message": "Invalid public key."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Save on the user model
        user = request.user
        user.public_key = public_key
        user.save()
        logger.info(f"[UPLOAD-KEY] Saved public key for user '{user.username}'.")
        return Response({"message": "Public key saved."}, status=status.HTTP_200_OK)

class UserMenuView(APIView):
    """
    Returns a small JSON object (or HTML template) listing user's options.
    Protected by session authentication.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response(
            {
                "message": f"Welcome, {user.username}!",
                "actions": {
                    "create_chat": "/chat/create-chat/",
                    "join_chat": "/chat/join-chat/",
                    "logout": "/chat/logout/",
                },
            }
        )
from rest_framework.authentication import TokenAuthentication


class CreateChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Create a new 4-digit PIN for a chat and save to database.
        Returns: { "chat_id": "<4-digit-string>" }
        """
        # Generate a unique 4-digit PIN
        while True:
            pin = f"{random.randint(0, 9999):04d}"
            if not Chat.objects.filter(pin=pin).exists():
                break

        # Create database record
        chat = Chat.objects.create(pin=pin, user1=request.user)
        logger.info(f"[CREATE-CHAT] Created chat in database: {chat}, PIN: {chat.pin}")

        # Verify it was saved
        saved_chat = Chat.objects.get(pin=pin)
        logger.info(f"[CREATE-CHAT] Verified chat exists: {saved_chat}")

        # Also initialize in-memory for compatibility
        active_chats[pin] = [request.user]
        request.session["chat_id"] = chat.pin
        logger.info(f"[CREATE-CHAT] PIN '{pin}' created (no participants yet).")
        return Response({"chat_id": pin}, status=201)


class JoinChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Join an existing chat by PIN.
        Expects JSON: { "chat_id": "<4-digit-PIN>" }
        """
        chat_id = request.data.get("chat_id")
        logger.info(f"[JOIN-CHAT] Attempting to join chat with ID: '{chat_id}'")
        logger.info(f"[JOIN-CHAT] Request data: {request.data}")

        if not chat_id:
            logger.warning("[JOIN-CHAT] No chat_id provided in request")
            return Response({"message": "Chat ID is required."}, status=400)

        try:
            chat = Chat.objects.get(pin=chat_id)
            logger.info(f"[JOIN-CHAT] Found chat: {chat}")
        except Chat.DoesNotExist:
            logger.warning(f"[JOIN-CHAT] Chat with PIN '{chat_id}' not found")
            return Response({"message": "Chat not found."}, status=404)

        # Assign the user to the chat if possible
        user = request.user
        if chat.user1 is None:
            chat.user1 = user
        elif chat.user2 is None and chat.user1 != user:
            chat.user2 = user
        elif user not in [chat.user1, chat.user2]:
            return Response({"message": "Chat is full."}, status=400)

        chat.save()

        # Update session for chatbox view
        request.session["chat_id"] = chat.pin

        # Update in-memory chat participant tracking
        if chat.pin not in active_chats:
            active_chats[chat.pin] = []
        if user not in active_chats[chat.pin]:
            active_chats[chat.pin].append(user)

        logger.info(f"[JOIN-CHAT] User '{user.username}' joined chat '{chat_id}'")
        return Response({"message": "Joined chat successfully."}, status=200)

    # Rest of your existing code...
# Check Active Chat View
class CheckChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        try:
            chat = Chat.objects.get(pin=chat_id)
            participants = []
            if chat.user1:
                participants.append(chat.user1.username)
            if chat.user2:
                participants.append(chat.user2.username)

            return Response({"exists": True, "participants": participants}, status=status.HTTP_200_OK)
        except Chat.DoesNotExist:
            return Response({"exists": False}, status=status.HTTP_404_NOT_FOUND)


# Leave Chat View - deletes the chat session and clears the message history
class LeaveChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        chat_id = request.data.get("chat_id", None)

        try:
            chat = Chat.objects.get(pin=chat_id)
        except Chat.DoesNotExist:
            return Response({"message": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        # Remove user from chat
        if chat.user1 == request.user:
            chat.user1 = None
        elif chat.user2 == request.user:
            chat.user2 = None
        else:
            return Response({"message": "Not in this chat."}, status=status.HTTP_400_BAD_REQUEST)

        # If no users left, mark as inactive or delete
        if chat.user1 is None and chat.user2 is None:
            chat.is_active = False
            chat.save()
            # Remove from in-memory tracking
            if chat_id in active_chats:
                del active_chats[chat_id]
        else:
            chat.save()
            # Update in-memory tracking
            if chat_id in active_chats and request.user in active_chats[chat_id]:
                active_chats[chat_id].remove(request.user)

        logger.info(f"[LEAVE-CHAT] User '{request.user.username}' left chat '{chat_id}'.")
        return Response({"message": "Left chat."}, status=status.HTTP_200_OK)

# Send Message View - saves a message in the database
from chat.client.enc_test_keygen.RSAEncryptor import (
    generate_aes_key, encrypt_with_aes, encrypt_aes_key_with_rsa, sign_message, verify_signature
)


# Updated SendMessageView in views.py
class SendMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Expects JSON:
          {
            "chat_id": "<4-digit-PIN>",
            "encrypted_text": "<base64-encoded RSA-OAEP ciphertext>",
            "signature":      "<base64-encoded RSA-PSS signature over the ciphertext>"
          }
        """
        try:
            logger.info("[SEND] Starting send flow for user '%s'", request.user.username)

            chat_id        = request.data.get("chat_id")
            encrypted_text = request.data.get("encrypted_text")
            signature      = request.data.get("signature")

            # 1) Validate required fields
            if not all([chat_id, encrypted_text, signature]):
                return Response(
                    {"message": "Missing required encryption fields."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 2) Validate chat existence
            if chat_id not in active_chats:
                logger.warning("[SEND] Invalid chat_id '%s'", chat_id)
                return Response({"message": "Invalid chat ID."}, status=status.HTTP_400_BAD_REQUEST)

            users = active_chats[chat_id]
            if len(users) < 2:
                return Response({"message": "Chat partner not found."}, status=status.HTTP_400_BAD_REQUEST)

            # 3) Ensure sender is a participant
            user1, user2 = users
            if request.user not in (user1, user2):
                logger.warning(
                    "[SEND] User '%s' not participant in chat '%s'",
                    request.user.username,
                    chat_id,
                )
                return Response({"message": "Not a participant."}, status=status.HTTP_403_FORBIDDEN)

            # 4) Determine the receiver
            receiver = user2 if request.user == user1 else user1
            logger.info("[SEND] Storing encrypted message for receiver '%s'", receiver.username)

            # 5) Create Message record—AES fields left blank/NULL
            msg = Message.objects.create(
                sender=request.user,
                receiver=receiver,
                encrypted_text=encrypted_text,
                encrypted_symmetric_key="",  # no AES key in this flow
                aes_nonce="",
                aes_tag="",
                signature=signature,
            )

            logger.info("[SEND] Stored Message(id=%s) with RSA-only encryption", msg.id)
            return Response({"message": "Message sent."}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("[SEND] ERROR: %s", str(e), exc_info=True)
            return Response({"error": "Failed to send message"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



from chat.client.enc_test_keygen.RSAEncryptor import (
    decrypt_with_aes, decrypt_aes_key_with_rsa
)


# Updated GetMessagesView in views.py
class GetMessagesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        logger.info(f"[GET] Retrieving encrypted messages for chat '{chat_id}' and user '{request.user.username}'")

        try:
            chat = Chat.objects.get(pin=chat_id)
        except Chat.DoesNotExist:
            logger.warning(f"[GET] Chat with PIN '{chat_id}' not found")
            return Response({"message": "Chat not found."}, status=404)

        users = active_chats.get(chat_id, [])

        if request.user not in users:
            logger.warning(f"[GET] User '{request.user.username}' not a participant in chat '{chat_id}'")
            return Response(status=status.HTTP_403_FORBIDDEN)

        # Determine the other participant
        partner = None
        if chat.user1 and chat.user1 != request.user:
            partner = chat.user1
        elif chat.user2 and chat.user2 != request.user:
            partner = chat.user2

        messages = Message.objects.filter(chat=chat).order_by("timestamp")
        serialized = MessageSerializer(messages, many=True)

        logger.info(f"[GET] Retrieved {len(messages)} encrypted messages for chat '{chat_id}'")

        return Response({
            "messages": serialized.data,
            "partner": partner.username if partner else None,
            "current_user": request.user.username,
            "both_joined": bool(chat.user1 and chat.user2)
        }, status=200)




@login_required
def setup_2fa(request):
    user = request.user

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    otp_uri = totp.provisioning_uri(name=user.username, issuer_name='Secure Chat')

    qr_img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    qr_data = base64.b64encode(buffer.getvalue()).decode()

    if request.method == 'POST':
        code = request.POST.get('otp_code')
        if totp.verify(code):
            user.is_2fa_enabled = True
            user.save()
            messages.success(request, '2FA activated successfully.')
            return redirect('usermenu')
        else:
            messages.error(request, 'Invalid code, please try again.')

    return render(request, 'chat/2fa_setup.html', {
        'qr_data': qr_data,
    })