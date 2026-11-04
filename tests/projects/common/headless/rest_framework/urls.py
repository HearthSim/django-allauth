from django.urls import path

from rest_framework.permissions import IsAuthenticated

from allauth.headless.contrib.rest_framework.authentication import (
    JWTTokenAuthentication,
    XSessionTokenAuthentication,
)

from .views import ResourceView


urlpatterns = [
    path(
        "jwt-resource",
        ResourceView.as_view(
            authentication_classes=[JWTTokenAuthentication],
            permission_classes=[IsAuthenticated],
        ),
        name="headless_rest_framework_jwt_resource",
    ),
    path(
        "session-resource",
        ResourceView.as_view(
            authentication_classes=[XSessionTokenAuthentication],
            permission_classes=[IsAuthenticated],
        ),
        name="headless_rest_framework_session_resource",
    ),
]
