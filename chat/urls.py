from django.urls import path
from .views import RegisterUserView, LoginView, MatchUserView, CheckChatView, LeaveChatView, auth_page

urlpatterns = [
    path("register/", RegisterUserView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("match/", MatchUserView.as_view(), name="match"),
    path("check-chat/", CheckChatView.as_view(), name="check-chat"),  # ✅ Import now works
    path("leave-chat/", LeaveChatView.as_view(), name="leave-chat"),
    path("", auth_page, name="auth_page"),
]

