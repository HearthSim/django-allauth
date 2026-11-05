from __future__ import annotations

from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from ninja.security.base import AuthBase

from allauth.core.internal.httpkit import get_authorization_credential
from allauth.headless import app_settings
from allauth.headless.internal.sessionkit import authenticate_by_x_session_token
from allauth.headless.tokens.strategies.jwt import internal
from allauth.usersessions.internal import usersessionkit


def _anonymous_user(request: HttpRequest) -> AnonymousUser:
    user = AnonymousUser()
    request.user = user
    return user


class XSessionTokenAuth(AuthBase):
    """
    This security class uses the X-Session-Token that django-allauth
    is using for authentication purposes.
    """

    openapi_type: str = "apiKey"
    allow_anonymous_users = False
    allow_invalid_session_tokens = False

    def __call__(self, request: HttpRequest):
        token = self.get_session_token(request)
        if not token:
            return _anonymous_user(request) if self.allow_anonymous_users else None
        result = authenticate_by_x_session_token(token)
        if result is None:
            if self.allow_invalid_session_tokens:
                return _anonymous_user(request)
            return None
        if result.user is None:
            return _anonymous_user(request) if self.allow_anonymous_users else None
        usersessionkit.track_activity(request, user=result.user, session=result.session)
        request.user = result.user  # type: ignore[assignment]
        return result.user

    def get_session_token(self, request: HttpRequest) -> str | None:
        """
        Returns the session token for the given request, by looking up the
        ``X-Session-Token`` header. Override this if you want to extract the token
        from e.g. the ``Authorization`` header.
        """
        return request.headers.get("X-Session-Token")


x_session_token_auth = XSessionTokenAuth()


class JWTTokenAuth(AuthBase):
    openapi_type: str = "apiKey"
    allow_anonymous_users = False

    def __call__(self, request: HttpRequest):
        token = get_authorization_credential(
            request, app_settings.JWT_AUTHORIZATION_HEADER_SCHEME
        )
        if token is None:
            return _anonymous_user(request) if self.allow_anonymous_users else None
        result = internal.validate_access_token(token)
        if result is None:
            return None
        usersessionkit.track_activity(request, user=result.user, session=result.session)
        request.user = result.user  # type: ignore[assignment]
        return result.payload


jwt_token_auth = JWTTokenAuth()
