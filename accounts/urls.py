from django.urls import path
from .views import (
    RegisterView,
    VerifyEmailView,
    LoginView,
    UserProfileView,
    PasswordChangeView,
    PasswordResetRequestView,  # 🔹 New import
    PasswordResetConfirmView,  # 🔹 New import
    LogoutView,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    path("login/", LoginView.as_view(), name="login"),
    path("me/", UserProfileView.as_view(), name="user-profile"),
    path("password/change/", PasswordChangeView.as_view(), name="password-change"),
    # 🔗 Remember Section 01, §1.1: Planned endpoints for password reset
    path(
        "password/reset/",
        PasswordResetRequestView.as_view(),
        name="password-reset-request",
    ),
    path(
        "password/reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
]
