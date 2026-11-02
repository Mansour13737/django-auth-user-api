from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from .serializers import RegisterSerializer

User = get_user_model()


class RegisterView(APIView):
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
