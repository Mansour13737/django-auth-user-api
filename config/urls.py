from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    # 🔗 Remember Section 01, §1.1: All our API endpoints are under /api/auth/
    path("api/auth/", include("accounts.urls")),
    # 🔗 Remember Project Prompt §8: OpenAPI Schema and Swagger UI
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]
