import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APIClient

User = get_user_model()


@pytest.mark.django_db
class TestTokenManagement:

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            email="tokenuser@example.com",
            password="strongpassword123",
            is_active=True,
            is_email_verified=True,
        )

    @pytest.fixture
    def auth_client(self, user):
        """Returns a client authenticated with an access token."""
        client = APIClient()
        refresh = RefreshToken.for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")
        return client

    def test_successful_logout(self, auth_client, user):
        """
        Test 1: Logout should blacklist the refresh token.
        🔗 Remember Section 01, §1.2.9: The token goes to the BlacklistedToken table.
        """
        url = reverse("logout")
        refresh = RefreshToken.for_user(user)

        payload = {"refresh": str(refresh)}
        response = auth_client.post(url, payload, content_type="application/json")

        assert response.status_code == 205
        assert response.json()["message"] == "Successfully logged out."

    def test_logout_with_invalid_token(self, auth_client):
        """
        Test 2: Logout with a fake or malformed token should fail.
        """
        url = reverse("logout")
        payload = {"refresh": "fake.token.here"}
        response = auth_client.post(url, payload, content_type="application/json")

        assert response.status_code == 400
        assert response.json()["error"] == "Invalid or expired token."

    def test_token_refresh_rotation(self, client, user):
        """
        Test 3: Refreshing a token should return a NEW access and NEW refresh token.
        🔗 Remember Section 01, §1.2.8: Rotation issues a new refresh token.
        """
        url = reverse("token-refresh")
        refresh = RefreshToken.for_user(user)
        old_refresh_str = str(refresh)

        payload = {"refresh": old_refresh_str}
        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 200
        assert "access" in response.json()
        assert "refresh" in response.json()

        # 🔹 The new refresh token MUST be different from the old one
        new_refresh_str = response.json()["refresh"]
        assert old_refresh_str != new_refresh_str

    def test_old_refresh_token_is_blacklisted(self, client, user):
        """
        Test 4: The old refresh token cannot be used again after rotation.
        🔗 Remember Section 01, §1.2.9: Rotation blacklists the old token.
        """
        url = reverse("token-refresh")
        refresh = RefreshToken.for_user(user)
        old_refresh_str = str(refresh)

        # 1. First request: Rotate the token
        payload = {"refresh": old_refresh_str}
        response1 = client.post(url, payload, content_type="application/json")
        assert response1.status_code == 200

        # 2. Second request: Try to use the OLD token again (Replay Attack)
        response2 = client.post(url, payload, content_type="application/json")

        assert response2.status_code == 401
        assert response2.json()["detail"] == "Token is blacklisted"
