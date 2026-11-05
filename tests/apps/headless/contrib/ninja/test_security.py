from http import HTTPStatus

from django.contrib.auth import HASH_SESSION_KEY
from django.contrib.auth.models import AnonymousUser

import pytest

from allauth.headless.constants import Client
from allauth.headless.contrib.ninja.security import (
    JWTTokenAuth,
    XSessionTokenAuth,
    jwt_token_auth,
    x_session_token_auth,
)


def test_authenticate(rf, user, headless_client, auth_client):
    if headless_client == Client.BROWSER:
        return
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)
    auth_user = XSessionTokenAuth()(request)
    assert auth_user.pk == user.pk


def test_invalid_authentication(rf, user, headless_client, auth_client):
    if headless_client == Client.BROWSER:
        return
    request = rf.get("/", HTTP_X_SESSION_TOKEN="wrong")
    result = XSessionTokenAuth()(request)
    assert result is None


def test_invalid_authentication_allowed(rf, db):
    class InvalidTokenAllowedAuth(XSessionTokenAuth):
        allow_invalid_session_tokens = True

    request = rf.get("/", HTTP_X_SESSION_TOKEN="wrong")
    result = InvalidTokenAllowedAuth()(request)
    assert isinstance(result, AnonymousUser)
    assert request.user is result


def test_anonymous_authentication_does_not_allow_invalid_token(rf, db):
    class AnonymousAllowedAuth(XSessionTokenAuth):
        allow_anonymous_users = True

    request = rf.get("/", HTTP_X_SESSION_TOKEN="wrong")
    assert AnonymousAllowedAuth()(request) is None


def test_anonymous_authentication_without_session_token(rf):
    class AnonymousAllowedAuth(XSessionTokenAuth):
        allow_anonymous_users = True

    request = rf.get("/")
    result = AnonymousAllowedAuth()(request)
    assert isinstance(result, AnonymousUser)
    assert request.user is result


def test_authenticate_rejects_stale_session_auth_hash(
    rf, user, headless_client, auth_client, password_factory
):
    if headless_client == Client.BROWSER:
        return
    user.set_password(password_factory())
    user.save()
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)
    assert XSessionTokenAuth()(request) is None


def test_anonymous_authentication_allows_stale_session_auth_hash(
    rf, user, headless_client, auth_client, password_factory
):
    if headless_client == Client.BROWSER:
        return
    user.set_password(password_factory())
    user.save()
    request = rf.get("/", HTTP_X_SESSION_TOKEN=auth_client.session_token)

    class AnonymousAllowedAuth(XSessionTokenAuth):
        allow_anonymous_users = True

    result = AnonymousAllowedAuth()(request)
    assert isinstance(result, AnonymousUser)
    assert request.user is result


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
    auth_user = XSessionTokenAuth()(request)
    assert auth_user.pk == user.pk
    assert request.user == auth_user


def test_authenticate_with_unusable_password(rf, user, headless_client, client):
    if headless_client == Client.BROWSER:
        return
    user.set_unusable_password()
    user.save(update_fields=["password"])
    client.force_login(user)
    request = rf.get("/", HTTP_X_SESSION_TOKEN=client.session_token)
    auth_user = XSessionTokenAuth()(request)
    assert auth_user.pk == user.pk


def test_jwt_anonymous_authentication(rf):
    class AnonymousAllowedAuth(JWTTokenAuth):
        allow_anonymous_users = True

    request = rf.get("/")
    result = AnonymousAllowedAuth()(request)
    assert isinstance(result, AnonymousUser)
    assert request.user is result


def test_jwt_anonymous_authentication_rejects_invalid_token(rf):
    class AnonymousAllowedAuth(JWTTokenAuth):
        allow_anonymous_users = True

    request = rf.get("/", HTTP_AUTHORIZATION="Bearer wrong")
    assert AnonymousAllowedAuth()(request) is None


@pytest.mark.parametrize(
    "auth,viewname",
    [
        (x_session_token_auth, "headless_ninja:session_resource"),
        (jwt_token_auth, "headless_ninja:jwt_resource"),
    ],
)
def test_anonymous_authentication_allows_resource(
    auth, viewname, client, headless_reverse, monkeypatch
):
    monkeypatch.setattr(auth, "allow_anonymous_users", True)
    response = client.get(headless_reverse(viewname))
    assert response.status_code == HTTPStatus.OK
    assert isinstance(response.wsgi_request.user, AnonymousUser)
