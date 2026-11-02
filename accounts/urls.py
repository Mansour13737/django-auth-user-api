from django.urls import path
from .views import RegisterView, VerifyEmailView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    # 🔗 Remember Section 02, §2.1.1: The endpoint for the user to click
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email"),
]
