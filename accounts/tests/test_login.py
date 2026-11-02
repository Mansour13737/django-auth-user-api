import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestLogin:

    @pytest.fixture
    def active_user(self):
        """Helper fixture to create a verified, active user for testing."""
        return User.objects.create_user(
            email="verified@example.com",
            password="strongpassword123",
            is_active=True,
            is_email_verified=True,
        )

    def test_successful_login(self, client, active_user):
        """
        Test 1: Successful login.
        🔗 Remember Section 01, §1.2.4: Should return access and refresh tokens.
        """
        url = reverse("login")
        payload = {"email": "verified@example.com", "password": "strongpassword123"}

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 200
        assert "access" in response.json()
        assert "refresh" in response.json()

    def test_invalid_password(self, client, active_user):
        """
        Test 2: Invalid password.
        🔗 Remember Section 01, §1.2.12: Must return a generic error to prevent enumeration.
        """
        url = reverse("login")
        payload = {"email": "verified@example.com", "password": "wrongpassword"}

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password."

    def test_unverified_user(self, client):
        """
        Test 3: Unverified user trying to log in.
        🔗 Remember Section 02, §2.1.1: Must be blocked with a specific message.
        """
        # Create a user who hasn't verified their email
        User.objects.create_user(
            email="unverified@example.com",
            password="strongpassword123",
            is_active=False,
            is_email_verified=False,
        )

        url = reverse("login")
        payload = {"email": "unverified@example.com", "password": "strongpassword123"}

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 401
        assert (
            response.json()["detail"] == "Please verify your email before logging in."
        )
