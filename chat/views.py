from django.contrib.auth import authenticate, get_user_model
from django.utils.timezone import now
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView
from .serializers import UserSerializer

User = get_user_model()

# Queue for matchmaking
queue = []  # Stores waiting users for chat sessions
active_chats = {}  # Maps chat IDs to user pairs

#  Home Page View
def home(request):
    return render(request, "index.html")

#  Authentication Page View (Login/Register UI)
def auth_page(request):
    return render(request, "auth.html")

#  User Registration
class RegisterUserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

#  User Login
class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)

        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key})
        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

#  Matchmaking Queue
class MatchUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        if user in queue:
            return Response({"message": "You are already in the queue"}, status=status.HTTP_400_BAD_REQUEST)

        queue.append(user)

        if len(queue) >= 2:
            user1 = queue.pop(0)
            user2 = queue.pop(0)
            chat_id = f"{user1.id}_{user2.id}_{int(now().timestamp())}"
            active_chats[chat_id] = (user1, user2)

            return Response({
                "message": "Matched successfully!",
                "chat_id": chat_id,
                "partner": user2.username
            }, status=status.HTTP_200_OK)

        return Response({"message": "Waiting for a match..."}, status=status.HTTP_202_ACCEPTED)

# Check Active Chat
class CheckChatView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        for chat_id, (user1, user2) in active_chats.items():
            if user in (user1, user2):
                return Response({
                    "chat_id": chat_id,
                    "partner": user2.username if user == user1 else user1.username
                }, status=status.HTTP_200_OK)
        return Response({"message": "No active chat found."}, status=status.HTTP_404_NOT_FOUND)

#  Leave Chat
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
            del active_chats[chat_to_remove]
            return Response({"message": "You left the chat."}, status=status.HTTP_200_OK)

        return Response({"message": "No active chat to leave."}, status=status.HTTP_400_BAD_REQUEST)

