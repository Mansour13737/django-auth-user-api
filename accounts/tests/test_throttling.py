import pytest
from django.urls import reverse
from django.core.cache import cache


# 🔹 Professional Tip: DRF Throttling uses Django's cache to track requests.
# If we don't clear it, one test could fail because a previous test used up the limit!
@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()


@pytest.mark.django_db
class TestThrottling:

    def test_login_throttling(self, client):
        """
        Test 1: Brute-force protection on login.
        🔗 Remember Project Prompt §3: Stop attackers after 5 attempts.
        """
        url = reverse("login")
        payload = {"email": "hacker@example.com", "password": "wrongpassword"}

        # 1. Send 5 requests (Should all fail with 401 Unauthorized)
        for i in range(5):
            response = client.post(url, payload, content_type="application/json")
            assert response.status_code == 401, f"Request {i+1} should be 401"

        # 2. Send the 6th request (Should fail with 429 Too Many Requests)
        response = client.post(url, payload, content_type="application/json")
        assert response.status_code == 429
        assert "throttled" in response.json()["detail"].lower()

    def test_register_throttling(self, client):
        """
        Test 2: Brute-force protection on registration.
        🔗 Remember Section 12, Step 1: Limit is 10/hour.
        """
        url = reverse("register")
        payload = {
            "email": "spam@example.com",
            "password": "strongpassword123",
            "password_confirm": "strongpassword123",
        }

        # Send 10 requests (10/hour limit)
        for i in range(10):
            response = client.post(url, payload, content_type="application/json")
            # It might return 201 (created) or 400 (duplicate email), both are fine here
            assert response.status_code != 429

        # 11th request should be throttled
        response = client.post(url, payload, content_type="application/json")
        assert response.status_code == 429
