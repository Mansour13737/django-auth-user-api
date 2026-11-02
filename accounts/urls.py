from django.urls import path
from .views import RegisterView, VerifyEmailView, LoginView, UserProfileView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    path("login/", LoginView.as_view(), name="login"),
    # 🔗 Remember Section 01, §1.2.13: The 'me' endpoint enforces object-level access
    path("me/", UserProfileView.as_view(), name="user-profile"),
]
