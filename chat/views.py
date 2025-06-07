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
from .serializers import UserSerializer
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
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import ChatSession, Message
from .serializers import MessageSerializer
from django.shortcuts import get_object_or_404
from rest_framework.permissions import AllowAny



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
def auth_page(request):
    return render(request, "auth.html")


def user_menu(request):
    return render(request, "usermenu.html")


# Chatbox Page View - renders chatbox.html
def chat_box(request):
    return render(request, "chatbox.html")

active_chats = {}

from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        return Response({'token': token.key, 'username': token.user.username})



# User Registration View
# Explicitly use the custom User model (chat_user)
User = get_user_model()

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_or_create_chat(request):
    user = request.user

    # Check if user is already in a chat
    existing_chat = ChatSession.objects.filter(Q(user1=user) | Q(user2=user)).first()
    if existing_chat:
        chat = existing_chat
    else:
        # Try to find another user not in a chat
        all_other_users = User.objects.exclude(id=user.id)
        for other_user in all_other_users:
            if not ChatSession.objects.filter(Q(user1=other_user) | Q(user2=other_user)).exists():
                chat = ChatSession.objects.create(user1=user, user2=other_user)
                break
        else:
            return Response({"detail": "No available users to match with"}, status=404)

    partner = chat.user2 if chat.user1 == user else chat.user1
    return Response({
        "chat_id": chat.id,
        "partner_username": partner.username
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_messages(request, chat_id):
    chat = get_object_or_404(ChatSession, id=chat_id)

    if request.user not in [chat.user1, chat.user2]:
        return Response({'detail': 'You are not a participant in this chat.'}, status=403)

    messages = chat.messages.order_by('timestamp')
    serializer = MessageSerializer(messages, many=True, context={'request': request})
    partner = chat.user2 if chat.user1 == request.user else chat.user1

    return Response({
        'partner': partner.username,
        'messages': serializer.data
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_message(request, chat_id):
    chat = get_object_or_404(ChatSession, id=chat_id)

    if request.user not in [chat.user1, chat.user2]:
        return Response({'detail': 'You are not a participant in this chat.'}, status=403)

    text = request.data.get('text', '').strip()
    if not text:
        return Response({'error': 'Message text cannot be empty.'}, status=400)

    message = Message.objects.create(
        chat=chat,
        sender=request.user,
        text=text
    )

    return Response({
        'status': 'Message sent',
        'message_id': message.id
    })

class RegisterUserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny] 

    def create(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        # Backend input validation
        if not is_valid_username(username):
            return Response({"message": "Username contains invalid characters."}, status=400)

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

def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None


class LoginView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        # Extract credentials and optional OTP
        username = request.data.get("username")
        password = request.data.get("password")
        otp_code = request.data.get("otp_code")  # optional, for 2FA
        
        # —— Rate limiting by IP ——
        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))
        
         # Initialize IP fail record if missing
        if ip not in failed_login_ips:
            failed_login_ips[ip] = {"fail_count": 0, "last_time": 0, "wait_time": 0}
        entry = failed_login_ips[ip]

        now_time = time.time()
        entry = failed_login_ips[ip]
        fail_count = entry["fail_count"]
        last_time = entry["last_time"]
        wait_time = entry["wait_time"]

        # If too many failures and still in cooldown, reject immediately
        if fail_count >= 3 and now_time < last_time + wait_time:
            wait_remaining = int(last_time + wait_time - now_time)
            return Response(
                {"message": f"Too many failed attempts. Try again in {wait_remaining} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # —— Credential check ——
        logger.info(f"[LOGIN] Attempting login from IP {ip} with username: {username}")
        user = authenticate(request=request, username=username, password=password)


        if not user:
            # Increment failure count
            entry["fail_count"] += 1

            # If we've hit the threshold, start or extend the cooldown
            if entry["fail_count"] >= 3:
                entry["wait_time"] = entry["wait_time"] * 2 if entry["wait_time"] else 10
                entry["last_time"] = now_time
                logger.warning(
                    f"[LOGIN] IP {ip} exceeded login attempts. Timeout started for {entry['wait_time']}s"
                )
                return Response(
                    {"message": f"Too many failed attempts. Try again in {entry['wait_time']} seconds."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # Otherwise, tell them how many attempts remain
            remaining_attempts = max(0, 2 - entry["fail_count"])
            logger.warning(
                f"[LOGIN] Failed login for {username} from IP {ip} (Count={entry['fail_count']}, Attempts left={remaining_attempts})"
            )
            return Response(
                {"message": f"Invalid credentials. Remaining attempts before timeout: {remaining_attempts}"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # —— Successful authentication ——        
        logger.info(f"[LOGIN] Login successful for {username} from IP: {ip}")

        # Create a Django session so request.user is set later
        django_login(request, user)

        # If the user has 2FA enabled, verify the OTP code
        if getattr(user, "is_2fa_enabled", False):
            totp = pyotp.TOTP(user.totp_secret)
            if not otp_code or not totp.verify(otp_code):
                return Response(
                    {"detail": "Invalid or missing 2FA code"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # Reset the failure record for this IP
        failed_login_ips.pop(ip, None)

        # Issue (or retrieve) the DRF Token
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key})


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
        # Generate a 4‐digit PIN that isn’t already in active_chats
        while True:
            pin = "{:04d}".format(random.randint(0, 9999))
            if pin not in active_chats:
                break

        # Store the single‐user list under this PIN
        active_chats[pin] = [request.user]
        return Response({"chat_id": pin}, status=status.HTTP_201_CREATED)



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

        # 1) Make sure the chat_id is valid
        if chat_id not in active_chats:
            logger.warning("[GET] Chat '%s' not found", chat_id)
            return Response({"error": "Chat not found"}, status=status.HTTP_404_NOT_FOUND)

        users = active_chats[chat_id]  # could be a list of length 1 or 2
        # 2) If there's only one participant so far, return 204 (No Content).
        if len(users) < 2:
            # Deny if the caller isn't even that one participant
            if request.user not in users:
                logger.warning(
                    "[GET] User '%s' not participant in chat '%s'",
                    request.user.username, chat_id
                )
                return Response({"error": "Not a participant"}, status=status.HTTP_403_FORBIDDEN)
            # If they are the creator, but no one else has joined yet:
            return Response(status=status.HTTP_204_NO_CONTENT)

        # 3) Now that len(users) == 2, unpack safely
        user1, user2 = users
        if request.user not in (user1, user2):
            logger.warning(
                "[GET] User '%s' not participant in chat '%s'",
                request.user.username, chat_id
            )
            return Response({"error": "Not a participant"}, status=status.HTTP_403_FORBIDDEN)

        # 4) Filter messages between the two participants exactly as before:
        msgs = Message.objects.filter(
            Q(sender=user1, receiver=user2) | Q(sender=user2, receiver=user1)
        ).order_by("timestamp")

        # 5) Load the private key and decrypt each message, etc.
        #    (This is identical to what you already had below.)
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

                    # AES-decrypt ciphertext
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
                        logger.warning(
                            "[GET] Signature INVALID for Message(id=%d) — possible tampering", m.id
                        )
                        plaintext = "[Tampered] " + plaintext

                except Exception as e:
                    logger.error(
                        "[GET] Decryption/Verification failed for Message(id=%d): %s", m.id, e
                    )
                    plaintext = "[Decryption failed]"

            else:
                # If I was the sender, show “[Sent]” or cached plaintext
                plaintext = sent_messages_cache.get(m.id, "[Sent]")

            out.append({
                "id":             m.id,
                "sender_id":      m.sender.id,
                "sender_username": m.sender.username,
                "text":           plaintext,
                "timestamp":      m.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
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
            return redirect('user_menu')
        else:
            messages.error(request, 'Invalid code, please try again.')

    return render(request, 'chat/2fa_setup.html', {
        'qr_data': qr_data,
    })
