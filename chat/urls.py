from django.urls import path
from .views import (
    RegisterUserView, LoginView, MatchUserView, CheckChatView, LeaveChatView, auth_page,
    chat_box, SendMessageView, GetMessagesView  # import the new views
)

urlpatterns = [
    path("register/", RegisterUserView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("match/", MatchUserView.as_view(), name="match"),
    path("check-chat/", CheckChatView.as_view(), name="check-chat"),
    path("leave-chat/", LeaveChatView.as_view(), name="leave-chat"),
    # New endpoints:
    path("send-message/", SendMessageView.as_view(), name="send_message"),
    path("get-messages/<str:chat_id>/", GetMessagesView.as_view(), name="get_messages"),
    path("chatbox/", chat_box, name="chatbox"),
    path("", auth_page, name="auth_page"),
]

