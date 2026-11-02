from rest_framework import serializers
from django.contrib.auth import get_user_model

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
