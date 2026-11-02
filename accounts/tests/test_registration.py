import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestRegistration:

    def test_successful_registration(self, client):
        """
        Test 1: Successful registration.
        🔗 Remember Section 02, §2.1.1: User must be created with is_active=False.
        """
        url = reverse("register")
        payload = {
            "email": "newuser@example.com",
            "full_name": "New User",
            "password": "strongpassword123",
            "password_confirm": "strongpassword123",
        }

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 201
        assert User.objects.count() == 1

        user = User.objects.first()
        assert user.email == "newuser@example.com"
        assert user.is_active is False
        assert user.is_email_verified is False

    def test_duplicate_email(self, client):
        """
        Test 2: Duplicate email.
        🔗 Remember Section 02, §2.3: Email must be unique.
        """
        # Create the first user
        User.objects.create_user(email="existing@example.com", password="password123")

        url = reverse("register")
        payload = {
            "email": "existing@example.com",
            "full_name": "Duplicate",
            "password": "strongpassword123",
            "password_confirm": "strongpassword123",
        }

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 400
        assert "email" in response.json()
        assert User.objects.count() == 1  # No new user should be created

    def test_password_mismatch(self, client):
        """
        Test 3: Invalid registration (passwords do not match).
        🔗 Remember Section 01, §1.2.11: Serializers handle validation.
        """
        url = reverse("register")
        payload = {
            "email": "mismatch@example.com",
            "full_name": "Mismatch",
            "password": "strongpassword123",
            "password_confirm": "differentpassword123",
        }

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 400
        assert "password" in response.json()
        assert User.objects.count() == 0
