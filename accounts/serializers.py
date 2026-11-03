from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator  # 🔹 Add this!
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    # We need password_confirm to ensure the user typed it correctly
    password_confirm = serializers.CharField(write_only=True)

    # We override the password field to ensure it is write-only (never returned in JSON)
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ["email", "full_name", "password", "password_confirm"]

    def validate_email(self, value):
        """
        🔗 Remember Section 02, §2.3: Email case sensitivity.
        We must normalize the email to lowercase to prevent duplicate accounts.
        """
        value = value.lower()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, attrs):
        """
        Check that the two password fields match.
        """
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        """
        Create the user with the hashed password and unverified status.
        """
        # Remove password_confirm as it's not a model field
        validated_data.pop("password_confirm")

        # 🔗 Remember Section 02, §2.1.1: Create user as inactive and unverified
        # 🔗 Remember Section 01, Security Rule #1: UserManager hashes the password securely
        user = User.objects.create_user(
            email=validated_data["email"],
            full_name=validated_data.get("full_name", ""),
            password=validated_data["password"],
            is_active=False,
            is_email_verified=False,
        )

        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            email = email.lower()

            # 🔹 NEW: Check if the user exists and check their status BEFORE authenticate()
            from django.contrib.auth import get_user_model

            User = get_user_model()
            user_obj = User.objects.filter(email=email).first()

            if user_obj and user_obj.check_password(password):
                # 🔗 Remember Section 02, §2.1.1: Security checks
                if not user_obj.is_email_verified:
                    raise AuthenticationFailed(
                        "Please verify your email before logging in."
                    )
                if not user_obj.is_active:
                    raise AuthenticationFailed("This account is inactive.")

            # Now let Django do the official authentication
            user = authenticate(
                request=self.context.get("request"), email=email, password=password
            )

            # 🔗 Remember Section 01, §1.2.12: Generic message for wrong email/password
            if not user:
                raise AuthenticationFailed("Invalid email or password.")

            refresh = self.get_token(user)
            data = {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
            return data

        raise AuthenticationFailed("Must include 'email' and 'password'.")


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # 🔗 Remember Section 01, §1.6: Explicitly list safe fields.
        # NEVER use fields = '__all__' on a user model!
        fields = [
            "id",
            "email",
            "full_name",
            "role",
            "is_email_verified",
            "date_joined",
        ]

        # 🔗 Remember Section 02, §2.7.2: Role is app-level.
        # Make it read-only so users can't promote themselves to ADMIN via this endpoint.
        read_only_fields = ["id", "email", "role", "is_email_verified", "date_joined"]


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    new_password_confirm = serializers.CharField(write_only=True, required=True)

    def validate_old_password(self, value):
        """
        Check that the old password is correct.
        """
        user = self.context["request"].user
        # 🔗 Remember Section 01, §1.2.3: Use Django's check_password, never compare strings!
        if not user.check_password(value):
            raise serializers.ValidationError(
                "Your old password was entered incorrectly. Please enter it again."
            )
        return value

    def validate_new_password(self, value):
        """
        Check that the new password meets Django's security requirements.
        """
        user = self.context["request"].user
        # 🔗 Remember Section 01, §1.6: Trust user input without validation is a mistake.
        # This applies Django's built-in validators (length, common passwords, numeric-only, etc.)
        validate_password(value, user)
        return value

    def validate(self, attrs):
        """
        Check that the two new password fields match.
        """
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password": "The two password fields didn't match."}
            )
        return attrs

    def save(self, **kwargs):
        """
        Set the new password and save the user.
        """
        password = self.validated_data["new_password"]
        user = self.context["request"].user

        # 🔗 Remember Section 01, Security Rule #1: Hash the new password securely
        user.set_password(password)
        user.save()

        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        # 🔗 Remember Section 02, §2.3: Normalize email
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    new_password_confirm = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        uidb64 = attrs.get("uid")
        token = attrs.get("token")

        # 1. Decode the UID and find the user
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            # 🔗 Remember Section 01, §1.6: Generic error to prevent enumeration
            raise serializers.ValidationError({"error": "Invalid reset link."})

        # 2. Validate the token
        # 🔗 Remember Section 01, §1.2.15: The token is time-limited and signed
        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError({"error": "Invalid or expired token."})

        # 3. Check that new passwords match
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password": "Passwords do not match."}
            )

        # 4. Validate password strength
        validate_password(attrs["new_password"], user)

        # Save the user in the serializer context to use in the save() method
        self.user = user
        return attrs

    def save(self, **kwargs):
        # 🔗 Remember Section 01, §1.2.3: Hash the new password securely
        password = self.validated_data["new_password"]
        self.user.set_password(password)
        self.user.save()
        return self.user
