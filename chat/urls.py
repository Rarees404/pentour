# chat/urls.py

from django.urls import path

from . import views
from .views import (
    RegisterUserView,
    LoginView,
    CheckChatView,
    LeaveChatView,
    auth_page,
    SendMessageView,
    GetMessagesView,
    user_menu,
    CreateChatView,
    JoinChatView,
    setup_2fa, chatbox, GetPublicKeyView,
)

urlpatterns = [
    # 1) Registration & Login
    path("register/", RegisterUserView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),

    # 2) User Menu (renders usermenu.html)
    path("usermenu/", user_menu, name="user_menu"),

    # 3) 2FA setup route (keep this exactly as before)
    path("2fa/setup/", setup_2fa, name="setup_2fa"),
    path("get-public-key/<int:user_id>/", GetPublicKeyView.as_view(), name="get-public-key"),

    # 4) Chat‐related API endpoints
    path("check-chat/",     CheckChatView.as_view(),    name="check-chat"),
    path("leave-chat/<str:chat_id>/", LeaveChatView.as_view(), name="leave-chat"),
    path("send-message/<str:chat_id>/", SendMessageView.as_view(),  name="send_message"),
    path("get-messages/<str:chat_id>/", GetMessagesView.as_view(), name="get-messages"),
    path("create-chat/",    CreateChatView.as_view(),   name="create-chat"),
    path("join-chat/",      JoinChatView.as_view(),     name="join-chat"),

    # 5) Chatbox page (renders chatbox.html)
    path("chatbox/", chatbox, name="chatbox"),

    # 6) Root of /chat/ serves your auth page (login/register form)
    path("", views.auth_page, name="auth_page"),
]
