from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from drf_spectacular.utils import extend_schema

from .serializers import (
    RegisterSerializer,
    CustomTokenObtainPairSerializer,
    UserProfileSerializer,
    PasswordChangeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
)

User = get_user_model()


@extend_schema(
    summary="Register a new user",
    description="Creates a new inactive user account and sends a verification email. Does not return tokens.",
)
class RegisterView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "register"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Save the user
            user = serializer.save()

            # 🔗 Remember Section 02, §2.7.3: Generate stateless tokens
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Create the verification link
            verification_link = (
                f"http://localhost:8000/api/auth/verify-email/?uid={uid}&token={token}"
            )

            # 🔹 Print a CLEAN link to the terminal for easy copy-pasting
            print(
                f"\n--- COPY THIS LINK TO VERIFY ---\n{verification_link}\n--------------------------------\n"
            )

            # Send the email
            send_mail(
                subject="Verify your email address",
                message=f"Please click the link to verify your account: {verification_link}",
                from_email="noreply@auth-api.com",
                recipient_list=[user.email],
                fail_silently=False,
            )

            return Response(
                {
                    "message": "User registered successfully. Please check your email to verify your account."
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    summary="Verify Email Address",
    description="Takes the uid and token from the verification email link and activates the user account.",
)
class VerifyEmailView(APIView):
    def get(self, request):
        uidb64 = request.query_params.get("uid")
        token = request.query_params.get("token")

        if not uidb64 or not token:
            return Response(
                {"error": "Missing uid or token."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            # 🔗 Remember Section 01, §1.6: Prevent user enumeration
            return Response(
                {"error": "Invalid verification link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user is not None and default_token_generator.check_token(user, token):
            # 🔗 Remember Section 02, §2.1.1: Flip the flags
            if not user.is_email_verified:
                user.is_email_verified = True
                user.is_active = True
                user.save()
                return Response(
                    {"message": "Email verified successfully. You can now log in."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "Email is already verified."}, status=status.HTTP_200_OK
                )
        else:
            # 🔗 Remember Section 01, §1.2.15: Token is expired or tampered with
            return Response(
                {"error": "Invalid or expired verification token."},
                status=status.HTTP_400_BAD_REQUEST,
            )


@extend_schema(
    summary="User Login",
    description="Takes an email and password. Returns JWT access and refresh tokens if the user is verified and active.",
)
class LoginView(TokenObtainPairView):
    """
    Takes an email and password and returns a JWT access and refresh token.
    """

    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"


@extend_schema(
    summary="Get or Update User Profile",
    description="Retrieves the authenticated user's profile. Allows updating full_name. Read-only fields like role cannot be changed.",
)
class UserProfileView(RetrieveUpdateAPIView):
    """
    View and update the authenticated user's profile.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """
        🔗 Remember Section 01, §1.2.13: Object-level permission.
        """
        return self.request.user


@extend_schema(
    summary="Change Password",
    description="Allows an authenticated user to change their password by providing their old password and a new one.",
)
class PasswordChangeView(APIView):
    """
    Allow an authenticated user to change their password.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={"request": request},
        )

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Password updated successfully."}, status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    summary="Request Password Reset",
    description="Sends a password reset link to the provided email address. Always returns a generic message to prevent user enumeration.",
)
class PasswordResetRequestView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            try:
                user = User.objects.get(email=email)

                # 🔗 Remember Section 01, §1.2.15: Generate signed token
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                reset_link = (
                    f"http://localhost:3000/reset-password?uid={uid}&token={token}"
                )

                print(
                    f"\n--- COPY THIS LINK TO RESET ---\n{reset_link}\n-------------------------------\n"
                )

                send_mail(
                    subject="Password Reset Request",
                    message=f"Click the link to reset your password: {reset_link}",
                    from_email="noreply@auth-api.com",
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            except User.DoesNotExist:
                pass

            return Response(
                {
                    "message": "If an account with that email exists, a password reset link has been sent."
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    summary="Confirm Password Reset",
    description="Takes the uid, token, and new password to reset the user's password. Token becomes invalid after use.",
)
class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "message": "Password has been reset successfully. You can now log in."
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    summary="Logout User",
    description="Blacklists the provided refresh token to log the user out. The short-lived access token will expire naturally.",
)
class LogoutView(APIView):
    """
    Blacklist the refresh token to log the user out.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 🔗 Remember Section 01, §1.2.9: This adds the token to the BlacklistedToken table
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {"message": "Successfully logged out."},
                status=status.HTTP_205_RESET_CONTENT,
            )

        except TokenError:
            return Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )
