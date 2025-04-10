from django.contrib.auth import authenticate, get_user_model
from django.utils.timezone import now
from django.shortcuts import render
from django.db.models import Q
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
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'chat/client/enc_test_keygen/basicconcept.py')))
from chat.client.enc_test_keygen.basicconcept import MessageEncryptor



# In-memory storage for matchmaking; in production, consider a persistent solution.
queue = []        # Stores waiting users for chat sessions
active_chats = {} # Maps chat IDs to a tuple of user objects (user1, user2)
queue_lock = Lock()
# Home Page View - renders index.html
def home(request):
    return render(request, "index.html")

# Authentication Page View (Login/Register UI) - renders auth.html
def auth_page(request):
    return render(request, "auth.html")

# Chatbox Page View - renders chatbox.html
def chat_box(request):
    return render(request, "chatbox.html")

# User Registration View
# Explicitly use the custom User model (chat_user)
User = get_user_model()

class RegisterUserView(CreateAPIView):
    queryset = get_user_model().objects.all()
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        # Check if the username already exists in the correct User table
        if User.objects.filter(username=username).exists():
            return Response({"message": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Create new user
        user = User(username=username)
        user.set_password(password)  # Securely hash the password
        user.save()

        return Response({"message": "Registration successful!"}, status=status.HTTP_201_CREATED)

# User Login View
class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)

        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key})
        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

# Matchmaking Queue View
class MatchUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        with queue_lock:  # Prevent race conditions
            # Check if user is already in a chat
            for chat_id, (user1, user2) in active_chats.items():
                if user in (user1, user2):
                    partner = user2 if user == user1 else user1
                    return Response({
                        "chat_id": chat_id,
                        "partner": partner.username
                    }, status=status.HTTP_200_OK)

            # Remove user if already in queue (prevent duplicates)
            if user in queue:
                queue.remove(user)

            # Add to queue
            queue.append(user)

            # Try to match if we have 2+ users
            if len(queue) >= 2:
                user1 = queue.pop(0)
                user2 = queue.pop(0)
                chat_id = f"{user1.id}_{user2.id}_{int(time.time())}"
                active_chats[chat_id] = (user1, user2)
                return Response({
                    "chat_id": chat_id,
                    "partner": user2.username if user == user1 else user1.username
                }, status=status.HTTP_200_OK)

        return Response({"message": "Waiting for a match..."}, status=status.HTTP_202_ACCEPTED)

# Add this new view for leaving queue
class LeaveQueueView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        with queue_lock:
            if user in queue:
                queue.remove(user)
                return Response({"message": "Left queue"}, status=status.HTTP_200_OK)
        return Response({"message": "Not in queue"}, status=status.HTTP_400_BAD_REQUEST)
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
class SendMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        message_text = request.data.get("message")
        chat_id = request.data.get("chat_id")

        if chat_id not in active_chats:
            return Response({"message": "Invalid chat ID."}, status=status.HTTP_400_BAD_REQUEST)

        user1, user2 = active_chats[chat_id]
        if request.user not in (user1, user2):
            return Response({"message": "You are not a participant of this chat."}, status=status.HTTP_403_FORBIDDEN)

        receiver = user2 if request.user == user1 else user1
        encryptor = MessageEncryptor()
        encrypted_text = encryptor.encrypt_message(message_text)
        Message.objects.create(sender=request.user, receiver=receiver, encrypted_text=encrypted_text)

        return Response({"message": "Message sent."}, status=status.HTTP_200_OK)


# Get Messages View - retrieves all messages for a given chat session
class GetMessagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        if chat_id not in active_chats:
            return Response({"error": "Chat not found"}, status=status.HTTP_404_NOT_FOUND)

        user1, user2 = active_chats[chat_id]
        if request.user not in (user1, user2):
            return Response({"error": "Not a participant"}, status=status.HTTP_403_FORBIDDEN)

        messages = Message.objects.filter(
            Q(sender=user1, receiver=user2) | Q(sender=user2, receiver=user1)
        ).order_by('timestamp')

        decryptor = MessageEncryptor()
        messages_data = []

        for msg in messages:
            try:
                decrypted_text = decryptor.decrypt_message(msg.encrypted_text)
            except Exception as e:
                decrypted_text = "[Decryption failed]"

            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender.id,
                'sender_username': msg.sender.username,
                'text': decrypted_text,
                'timestamp': msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'is_current_user': msg.sender == request.user
            })

        return Response({
            'messages': messages_data,
            'current_user': request.user.username,  # Include current user info
            'partner': user2.username if request.user == user1 else user1.username
        })
