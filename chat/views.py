from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import authenticate, login as django_login
from django.db.models import Q
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView
from .serializers import UserSerializer, MessageSerializer
from .models import Message
import logging
import pyotp
import qrcode
import io
import base64
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from collections import defaultdict
import re
import random
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import Chat
from django.shortcuts import get_object_or_404
from .models import User
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication, BasicAuthentication



# Track failed login attempts per IP: {ip: (last_attempt_time, wait_time)}
failed_login_ips = defaultdict(lambda: {'last_time': 0, 'wait_time': 0, 'fail_count': 0})

logger = logging.getLogger(__name__)
# In-memory storage for matchmaking; in production, consider a persistent solution.
#queue = []        # Stores waiting users for chat sessions
#active_chats = {} # Maps chat IDs to a tuple of user objects (user1, user2)
#queue_lock = Lock()
#sent_messages_cache = {}  # {msg.id: plaintext}



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




@api_view(['GET'])
def get_public_key(request, partner_id):
    user = get_object_or_404(User, pk=partner_id)
    return Response({ 'public_key': user.public_key_pem })


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
        signing_public_key = request.data.get("signing_public_key")

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
        user = User(
                username=username,
                public_key=public_key,
                signing_public_key=signing_public_key
        )
        user.set_password(password)
        user.save()
        logger.info(f"[REGISTER] User created with client‐provided public key: {username}")

        return Response({"message": "Registration successful!"}, status=status.HTTP_201_CREATED)


def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None


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
    Accepts a JSON body:
      {
         "public_key": "<PEM string for RSA-OAEP encryption>",
         "signing_public_key": "<PEM string for RSA-PSS signature verification>"
      }
    and updates the currently authenticated user's keys.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Extract both PEMs
        encryption_pem = request.data.get("public_key")
        signing_pem = request.data.get("signing_public_key")

        if not encryption_pem:
            return Response(
                {"detail": "Missing public_key in request body."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = request.user

        # Save the encryption key
        user.public_key = encryption_pem

        # Optionally validate the PEM format here before saving…

        # Save the signing key if provided
        if signing_pem:
            user.signing_public_key = signing_pem

        user.save(update_fields=["public_key", "signing_public_key"])
        logger.info(f"[UPLOAD-KEY] Saved keys for user '{user.username}'.")
        return Response({"status": "ok"}, status=status.HTTP_200_OK)



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
        logger.info(f"[JOIN-CHAT] Incoming join request for PIN: {chat_id!r}")
        if not chat_id:
            logger.warning("[JOIN-CHAT] No 'chat_id' provided in payload.")
            return Response({"message": "Chat ID is required."}, status=400)

        #  Look up the Chat
        try:
            chat = Chat.objects.get(pin=chat_id)
            logger.info(f"[JOIN-CHAT] Chat found: {chat} (id={chat.pk})")
        except Chat.DoesNotExist:
            logger.warning(f"[JOIN-CHAT] No chat matching PIN={chat_id}")
            return Response({"message": "Chat not found."}, status=404)

        user = request.user
        logger.debug(f"[JOIN-CHAT] Current user: {user.username} (id={user.pk})")

        #  Persist the user into an open slot
        if chat.user1 is None:
            chat.user1 = user
            logger.info(f"[JOIN-CHAT] Assigned '{user.username}' to user1.")
        elif chat.user2 is None and chat.user1 != user:
            chat.user2 = user
            logger.info(f"[JOIN-CHAT] Assigned '{user.username}' to user2.")
        elif user in (chat.user1, chat.user2):
            logger.info(f"[JOIN-CHAT] '{user.username}' was already in this chat.")
        else:
            logger.warning(f"[JOIN-CHAT] Chat {chat_id} is already full.")
            return Response({"message": "Chat is full."}, status=400)

        #  Save the updated Chat record
        chat.save()
        logger.debug(f"[JOIN-CHAT] Chat record saved. user1={chat.user1}, user2={chat.user2}")

        #  Store chat_id in session so GetMessagesView sees it
        request.session["chat_id"] = chat.pin
        logger.debug(f"[JOIN-CHAT] chat_id stored in session.")

        #  Mirror in-memory tracking (optional, but useful if you rely on it elsewhere)
        active_list = active_chats.setdefault(chat.pin, [])
        if user not in active_list:
            active_list.append(user)
            logger.debug(f"[JOIN-CHAT] Added to active_chats in-memory list.")

        logger.info(f"[JOIN-CHAT] User '{user.username}' successfully joined chat '{chat_id}'.")
        return Response({"message": "Joined chat successfully."}, status=200)


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


class GetPublicKeyView(APIView):
    """
    GET /chat/get-public-key/<user_id>/
    Returns JSON:
      {
        "public_key": "<PEM for RSA-OAEP encryption>",
        "signing_public_key": "<PEM for RSA-PSS verification>"
      }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes     = [permissions.IsAuthenticated]

    def get(self, request, user_id, *args, **kwargs):
        # Look up the target user
        target = get_object_or_404(User, pk=user_id)

        if not target.public_key:
            return Response(
                {"detail": "No encryption public_key stored for this user."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Build response with both keys (signing key may be None)
        response_data = {
            "public_key": target.public_key,
            "signing_public_key": target.signing_public_key
        }

        logger.debug(f"[GET-KEY] Returning keys for user_id={user_id}")
        return Response(response_data, status=status.HTTP_200_OK)


class SendMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes     = [permissions.IsAuthenticated]

    def post(self, request, chat_id=None):
        chat = get_object_or_404(Chat, pin=chat_id)

        me = request.user
        if me != chat.user1 and me != chat.user2:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # Extract ALL required cryptographic fields
        encrypted_text = request.data.get("encrypted_text")
        encrypted_symmetric_key = request.data.get("encrypted_symmetric_key")
        aes_nonce = request.data.get("aes_nonce")
        aes_tag = request.data.get("aes_tag")
        signature = request.data.get("signature")
        # The frontend sends sender_public_key, but we can retrieve the sender's public key
        # directly from `me.public_key` when verifying a signature if needed,
        # or from `partner.public_key` if the message is from the partner.
        # So, no need to store sender_public_key explicitly with each message.

        # Validate that all crucial fields are present
        if not all([encrypted_text, encrypted_symmetric_key, aes_nonce, aes_tag, signature]):
            return Response(
                {"message": "Missing required encryption fields."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Determine the recipient
        recipient = chat.user2 if (me == chat.user1) else chat.user1

        # Create and save the Message with ALL cryptographic components
        msg = Message.objects.create(
            sender=me,
            receiver= recipient,
            encrypted_text=encrypted_text,
            encrypted_symmetric_key=encrypted_symmetric_key,
            aes_nonce=aes_nonce,
            aes_tag=aes_tag,
            signature=signature,
        )

        serializer_data = MessageSerializer(msg).data
        return Response(serializer_data, status=status.HTTP_201_CREATED)


class GetMessagesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes     = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        """
        GET /chat/get-messages/<chat_id>/
        Returns the encrypted messages between the two participants of this chat.
        """
        # 1) Load (or 404) the Chat by its 4-digit PIN
        chat = get_object_or_404(Chat, pin=chat_id)

        # 2) Verify the requesting user is one of the two participants
        me = request.user
        if me != chat.user1 and me != chat.user2:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # 3) Determine who the “partner” is
        partner = chat.user2 if (me == chat.user1) else chat.user1

        # 4) Fetch every Message whose (sender, receiver) pair matches (me ↔ partner)
        messages_qs = Message.objects.filter(
            (Q(sender=me) & Q(receiver=partner)) |
            (Q(sender=partner) & Q(receiver=me))
        ).order_by("timestamp")

        # 5) Serialize those messages
        serializer_data = MessageSerializer(messages_qs, many=True, context={'request': request}).data 

        # 6) Return JSON (including partner’s username/id and “both_joined” flag)
        return Response({
            "messages":     serializer_data,
            "partner":      partner.username if partner else None,
            "partner_id":   partner.id       if partner else None,
            "current_user": me.username,
            "both_joined":  bool(chat.user1 and chat.user2),
        }, status=status.HTTP_200_OK)



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