import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()


@pytest.mark.django_db
class TestPasswordReset:

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            email="reset@example.com",
            password="oldpassword123",
            is_active=True,
            is_email_verified=True,
        )

    def test_reset_request_for_fake_email(self, client):
        """
        Test 1: Requesting a reset for an email that doesn't exist.
        🔗 Remember Section 01, §1.2.12: Must return 200 OK to prevent enumeration.
        """
        url = reverse("password-reset-request")
        response = client.post(
            url, {"email": "fake@example.com"}, content_type="application/json"
        )

        assert response.status_code == 200
        assert (
            response.json()["message"]
            == "If an account with that email exists, a password reset link has been sent."
        )
        assert len(mail.outbox) == 0  # No email should be sent

    def test_reset_request_for_real_email(self, client, user):
        """
        Test 2: Requesting a reset for a real email.
        🔗 Remember Section 02, §2.1.6: Should generate an email with a link.
        """
        url = reverse("password-reset-request")
        response = client.post(
            url, {"email": "reset@example.com"}, content_type="application/json"
        )

        assert response.status_code == 200
        assert len(mail.outbox) == 1
        assert "Password Reset Request" in mail.outbox[0].subject
        assert "reset-password?uid=" in mail.outbox[0].body

    def test_successful_password_reset(self, client, user):
        """
        Test 3: Confirming the reset with a valid token.
        🔗 Remember Section 01, §1.2.3: Password must be updated securely.
        """
        # Manually generate the token for the test
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        url = reverse("password-reset-confirm")
        payload = {
            "uid": uid,
            "token": token,
            "new_password": "newstrongpassword123",
            "new_password_confirm": "newstrongpassword123",
        }

        response = client.post(url, payload, content_type="application/json")

        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_password("newstrongpassword123") is True

    def test_replay_attack(self, client, user):
        """
        Test 4: Trying to reuse the token after the password has changed.
        🔗 Remember Section 01, §1.2.15: Token must self-destruct.
        """
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        url = reverse("password-reset-confirm")
        payload = {
            "uid": uid,
            "token": token,
            "new_password": "newstrongpassword123",
            "new_password_confirm": "newstrongpassword123",
        }

        # First request: Success
        response1 = client.post(url, payload, content_type="application/json")
        assert response1.status_code == 200

        # Second request (Replay): Fail
        response2 = client.post(url, payload, content_type="application/json")
        assert response2.status_code == 400
        assert "Invalid or expired token" in response2.json()["error"][0]
