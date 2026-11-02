import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APIClient  # 🔹 Import APIClient directly

User = get_user_model()


@pytest.mark.django_db
class TestUserProfile:

    @pytest.fixture
    def authenticated_client(self, db):  # 🔹 Use 'db' fixture to allow database access
        """Helper fixture to create a user, generate a token, and log them in."""
        # 🔹 Manually create the DRF APIClient
        client = APIClient()

        user = User.objects.create_user(
            email="profile@example.com",
            password="strongpassword123",
            is_active=True,
            is_email_verified=True,
        )
        # Generate a real JWT token for this user
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Attach the token to the APIClient's headers
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        return client

    def test_unauthorized_access(self, client):
        """
        Test 1: Try to access /me/ without a token.
        🔗 Remember Section 01, §1.2.2: Must be blocked.
        """
        url = reverse("user-profile")
        response = client.get(url)

        # DRF returns 401 Unauthorized if no credentials are provided
        assert response.status_code == 401
        assert (
            response.json()["detail"] == "Authentication credentials were not provided."
        )

    def test_get_profile(self, authenticated_client):
        """
        Test 2: Get the profile of the logged-in user.
        🔗 Remember Section 01, §1.2.13: Should return the correct user's data.
        """
        url = reverse("user-profile")
        response = authenticated_client.get(url)

        assert response.status_code == 200
        assert response.json()["email"] == "profile@example.com"
        assert "password" not in response.json()  # Security check!

    def test_cannot_escalate_privileges(self, authenticated_client):
        """
        Test 3: Try to change the 'role' to ADMIN.
        🔗 Remember Section 02, §2.7.2: read_only_fields must prevent this.
        """
        url = reverse("user-profile")
        payload = {"role": "ADMIN"}

        response = authenticated_client.patch(
            url, payload, content_type="application/json"
        )

        assert response.status_code == 200
        # The role should NOT be updated because it's in read_only_fields
        assert response.json()["role"] == "USER"
