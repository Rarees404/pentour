from django.contrib.auth import authenticate, get_user_model
from django.utils.timezone import now
from django.shortcuts import render
from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView
from .serializers import UserSerializer
from .models import Message

# In-memory storage for matchmaking; in production, consider a persistent solution.
queue = []        # Stores waiting users for chat sessions
active_chats = {} # Maps chat IDs to a tuple of user objects (user1, user2)

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
class RegisterUserView(CreateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer

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

        if user in queue:
            return Response({"message": "You are already in the queue"}, status=status.HTTP_400_BAD_REQUEST)

        queue.append(user)

        if len(queue) >= 2:
            # Pop the two earliest users in the queue
            user1 = queue.pop(0)
            user2 = queue.pop(0)
            chat_id = f"{user1.id}_{user2.id}_{int(now().timestamp())}"
            active_chats[chat_id] = (user1, user2)
            # Determine the partner for the user making the request
            if user == user1:
                partner = user2.username
            else:
                partner = user1.username
            return Response({
                "message": "Matched successfully!",
                "chat_id": chat_id,
                "partner": partner
            }, status=status.HTTP_200_OK)

        return Response({"message": "Waiting for a match..."}, status=status.HTTP_202_ACCEPTED)

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
        # Determine receiver based on who is sending the message
        receiver = user2 if request.user == user1 else user1
        Message.objects.create(sender=request.user, receiver=receiver, encrypted_text=message_text)
        return Response({"message": "Message sent."}, status=status.HTTP_200_OK)

# Get Messages View - retrieves all messages for a given chat session
class GetMessagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        if chat_id not in active_chats:
            return Response({"message": "Invalid chat ID."}, status=status.HTTP_400_BAD_REQUEST)
        user1, user2 = active_chats[chat_id]
        if request.user not in (user1, user2):
            return Response({"message": "You are not a participant of this chat."}, status=status.HTTP_403_FORBIDDEN)
        messages = Message.objects.filter(
            Q(sender=user1, receiver=user2) | Q(sender=user2, receiver=user1)
        ).order_by("timestamp")
        messages_data = [{
            "sender": msg.sender.username,
            "text": msg.encrypted_text,
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for msg in messages]
        return Response({"messages": messages_data}, status=status.HTTP_200_OK)

