from django.urls import path
from .views import RegisterView, VerifyEmailView, LoginView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    # 🔗 Remember Section 01, §1.1: Planned endpoint for login
    path("login/", LoginView.as_view(), name="login"),
]
