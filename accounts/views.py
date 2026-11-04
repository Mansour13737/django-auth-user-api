from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from .serializers import RegisterSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from .serializers import UserProfileSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import PasswordChangeSerializer
from .serializers import PasswordResetRequestSerializer, PasswordResetConfirmSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.throttling import ScopedRateThrottle

User = get_user_model()


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


class LoginView(TokenObtainPairView):
    """
    Takes an email and password and returns a JWT access and refresh token.
    """

    # 🔗 Remember Section 01, §1.2.11: Swap the default serializer with our secure one
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"


class UserProfileView(RetrieveUpdateAPIView):
    """
    View and update the authenticated user's profile.
    """

    serializer_class = UserProfileSerializer

    # 🔗 Remember Section 01, §1.2.2: Authentication.
    # This forces the user to send a valid Bearer Access Token in the headers.
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """
        🔗 Remember Section 01, §1.2.13: Object-level permission.
        We override this to ALWAYS return the profile of the user making the request.
        This prevents User A from changing the ID in the URL to view User B's data.
        """
        return self.request.user


class PasswordChangeView(APIView):
    """
    Allow an authenticated user to change their password.
    """

    # 🔗 Remember Section 01, §1.2.2: Only authenticated users can access this
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            # 🔗 Remember Section 01, §1.2.11: We pass the request context so the serializer can access request.user
            context={"request": request},
        )

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Password updated successfully."}, status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            # 🔹 Check if user exists, but DO NOT reveal this to the client
            try:
                user = User.objects.get(email=email)

                # 🔗 Remember Section 01, §1.2.15: Generate signed token
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                reset_link = (
                    f"http://localhost:3000/reset-password?uid={uid}&token={token}"
                )

                # Print to terminal for easy testing
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
                pass  # Do nothing. We don't want to leak that the email doesn't exist.

            # 🔗 Remember Section 01, §1.2.12: Always return the same generic message
            return Response(
                {
                    "message": "If an account with that email exists, a password reset link has been sent."
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            # The serializer's save() method hashes the password and updates the user
            serializer.save()
            return Response(
                {
                    "message": "Password has been reset successfully. You can now log in."
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    Blacklist the refresh token to log the user out.
    """

    # 🔗 Remember Section 01, §1.2.2: Only logged-in users can log out
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # 1. Get the refresh token from the request body
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 2. Instantiate the token and blacklist it
            # 🔗 Remember Section 01, §1.2.9: This adds the token to the BlacklistedToken table
            token = RefreshToken(refresh_token)
            token.blacklist()

            # 🔗 Remember Section 01, Security Rule #9: 205 Reset Content is standard for logout
            return Response(
                {"message": "Successfully logged out."},
                status=status.HTTP_205_RESET_CONTENT,
            )

        except TokenError:
            # 🔗 Remember Section 01, §1.2.15: Token is invalid, expired, or already blacklisted
            return Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )
