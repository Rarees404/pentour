from django.urls import path
from .views import (
    RegisterUserView, LoginView, MatchUserView, CheckChatView, LeaveChatView, auth_page,
    chat_box, SendMessageView, GetMessagesView, LeaveQueueView,user_menu, CreateChatView, JoinChatView  # import the new views
)

urlpatterns = [
    path("register/", RegisterUserView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("usermenu/", user_menu, name="user_menu"),
    path("match/", MatchUserView.as_view(), name="match"),
    path("check-chat/", CheckChatView.as_view(), name="check-chat"),
    path("leave-chat/", LeaveChatView.as_view(), name="leave-chat"),
    path("leave-queue/", LeaveQueueView.as_view(), name="leave-queue"),
    # New endpoints:
    path("send-message/", SendMessageView.as_view(), name="send_message"),
    path("get-messages/<str:chat_id>/", GetMessagesView.as_view(), name="get_messages"),
    path("create-chat/", CreateChatView.as_view(), name="create_chat"),
    path("join-chat/", JoinChatView.as_view(), name="join_chat"),
    path("chatbox/", chat_box, name="chatbox"),
    path("", auth_page, name="auth_page"),

]

