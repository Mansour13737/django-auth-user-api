from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
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
