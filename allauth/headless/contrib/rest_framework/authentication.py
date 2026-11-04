from __future__ import annotations

from django.http import HttpRequest

from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from allauth.core import context
from allauth.headless import app_settings
from allauth.headless.internal.sessionkit import authenticate_by_x_session_token
from allauth.usersessions.internal import usersessionkit


def _get_http_request(request: HttpRequest | Request) -> HttpRequest:
    if isinstance(request, Request):
        return request._request
    return request


class XSessionTokenAuthentication(authentication.BaseAuthentication):
    """
    This authentication class uses the X-Session-Token that django-allauth
    is using for authentication purposes.
    """

    def authenticate(self, request: HttpRequest):
        token = self.get_session_token(request)
        if token:
            user_session = authenticate_by_x_session_token(token)
            if user_session:
                user, session = user_session
                usersessionkit.track_activity(
                    _get_http_request(request), user=user, session=session
                )
                return user_session
        return None

    def get_session_token(self, request: HttpRequest) -> str | None:
        """
        Returns the session token for the given request, by looking up the
        ``X-Session-Token`` header. Override this if you want to extract the token
        from e.g. the ``Authorization`` header.
        """
        return request.headers.get("X-Session-Token")


class JWTTokenAuthentication(authentication.TokenAuthentication):
    @property
    def keyword(self) -> str:
        """
        See: ``settings.HEADLESS_JWT_AUTHORIZATION_HEADER_SCHEME``.
        """
        return app_settings.JWT_AUTHORIZATION_HEADER_SCHEME

    def authenticate_credentials(self, key: str):
        """
        Validates the given access token.
        """
        from allauth.headless.tokens.strategies.jwt import internal

        result = internal.validate_access_token(key)
        if result is None:
            raise AuthenticationFailed("Invalid token.")
        usersessionkit.track_activity(
            context.request, user=result.user, session=result.session
        )
        return result.user, result.payload
