import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APIClient

User = get_user_model()


@pytest.mark.django_db
class TestPasswordChange:

    @pytest.fixture
    def authenticated_client(self, db):
        client = APIClient()
        user = User.objects.create_user(
            email="changepass@example.com",
            password="oldstrongpassword123",
            is_active=True,
            is_email_verified=True,
        )
        refresh = RefreshToken.for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")
        return client, user

    def test_unauthenticated_access(self, client):
        """
        Test 1: Cannot change password without logging in.
        🔗 Remember Section 01, §1.2.2: IsAuthenticated must block this.
        """
        url = reverse("password-change")
        payload = {
            "old_password": "oldstrongpassword123",
            "new_password": "newstrongpassword123",
            "new_password_confirm": "newstrongpassword123",
        }
        response = client.post(url, payload, content_type="application/json")
        assert response.status_code == 401

    def test_successful_password_change(self, authenticated_client):
        """
        Test 2: Happy path.
        🔗 Remember Section 01, §1.2.3: Passwords must be hashed securely.
        """
        client, user = authenticated_client
        url = reverse("password-change")
        payload = {
            "old_password": "oldstrongpassword123",
            "new_password": "newstrongpassword123",
            "new_password_confirm": "newstrongpassword123",
        }

        response = client.post(url, payload, content_type="application/json")
        assert response.status_code == 200

        # 🔗 Remember Section 01, §1.2.3: Verify the database was updated securely
        user.refresh_from_db()
        assert user.check_password("newstrongpassword123") is True
        assert user.check_password("oldstrongpassword123") is False

    def test_wrong_old_password(self, authenticated_client):
        """
        Test 3: User enters the wrong old password.
        🔗 Remember Section 01, §1.2.3: check_password must catch this.
        """
        client, _ = authenticated_client
        url = reverse("password-change")
        payload = {
            "old_password": "wrongoldpassword",
            "new_password": "newstrongpassword123",
            "new_password_confirm": "newstrongpassword123",
        }

        response = client.post(url, payload, content_type="application/json")
        assert response.status_code == 400
        assert "old_password" in response.json()
        assert (
            response.json()["old_password"][0]
            == "Your old password was entered incorrectly. Please enter it again."
        )

    def test_weak_new_password(self, authenticated_client):
        """
        Test 4: User tries to set a weak password.
        🔗 Remember Section 01, §1.6: Must validate user input.
        """
        client, _ = authenticated_client
        url = reverse("password-change")
        payload = {
            "old_password": "oldstrongpassword123",
            "new_password": "123",  # Too short
            "new_password_confirm": "123",
        }

        response = client.post(url, payload, content_type="application/json")
        assert response.status_code == 400
        assert "new_password" in response.json()
        # Django's default validators will catch this
        assert "This password is too short" in response.json()["new_password"][0]
