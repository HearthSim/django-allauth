from http import HTTPStatus

from django.contrib.auth import HASH_SESSION_KEY

import pytest
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from allauth.headless.constants import Client
from allauth.headless.contrib.rest_framework.authentication import (
    XSessionTokenAuthentication,
)


def test_authenticate(rf, user, headless_client, auth_client):
    if headless_client == Client.BROWSER:
        return
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)
    auth_user, session = XSessionTokenAuthentication().authenticate(request)
    assert auth_user.pk == user.pk


def test_invalid_authentication(rf, user, headless_client, auth_client):
    if headless_client == Client.BROWSER:
        return
    request = rf.get("/", HTTP_X_SESSION_TOKEN="wrong")
    result = XSessionTokenAuthentication().authenticate(request)
    assert result is None


def test_invalid_authentication_not_allowed(rf, db):
    class StrictXSessionTokenAuthentication(XSessionTokenAuthentication):
        allow_invalid_session_tokens = False

    class View(APIView):
        authentication_classes = [StrictXSessionTokenAuthentication]
        permission_classes = [AllowAny]

        def get(self, request):
            return Response()

    request = rf.get("/", HTTP_X_SESSION_TOKEN="wrong")
    response = View.as_view()(request)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.data["detail"] == "Invalid token."
    assert response["WWW-Authenticate"] == "X-Session-Token"


def test_authenticate_rejects_stale_session_auth_hash(
    rf, user, headless_client, auth_client, password_factory
):
    if headless_client == Client.BROWSER:
        return
    user.set_password(password_factory())
    user.save()
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)
    assert XSessionTokenAuthentication().authenticate(request) is None


def test_authenticate_rejects_anonymous_user_when_not_allowed(
    rf, user, headless_client, auth_client, password_factory
):
    if headless_client == Client.BROWSER:
        return
    user.set_password(password_factory())
    user.save()
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)

    class StrictXSessionTokenAuthentication(XSessionTokenAuthentication):
        allow_anonymous_users = False

    with pytest.raises(AuthenticationFailed, match="Incorrect authentication"):
        StrictXSessionTokenAuthentication().authenticate(request)


def test_authenticate_survives_session_auth_hash_update(
    rf, user, headless_client, auth_client, password_factory
):
    if headless_client == Client.BROWSER:
        return
    session = auth_client.headless_session()
    user.set_password(password_factory())
    user.save()
    session[HASH_SESSION_KEY] = user.get_session_auth_hash()
    session.save()
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)
    auth_user, _ = XSessionTokenAuthentication().authenticate(request)
    assert auth_user.pk == user.pk


def test_authenticate_with_unusable_password(rf, user, headless_client, client):
    if headless_client == Client.BROWSER:
        return
    user.set_unusable_password()
    user.save(update_fields=["password"])
    client.force_login(user)
    request = rf.get("/", HTTP_X_SESSION_TOKEN=client.session_token)
    auth_user, _ = XSessionTokenAuthentication().authenticate(request)
    assert auth_user.pk == user.pk
