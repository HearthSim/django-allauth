from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module

from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.sessions.backends.base import SessionBase
from django.http import HttpRequest

from allauth.core.internal.sessionkit import get_session_user
from allauth.headless import app_settings
from allauth.headless.constants import Client


@dataclass
class XSessionTokenAuthenticationResult:
    user: AbstractBaseUser | None
    session: SessionBase


def session_store(session_key=None) -> SessionBase:
    engine = import_module(settings.SESSION_ENGINE)
    return engine.SessionStore(session_key=session_key)


def new_session() -> SessionBase:
    return session_store()


def expose_session_token(request: HttpRequest) -> str | None:
    if request.allauth.headless.client != Client.APP:  # type: ignore[attr-defined]
        return None
    strategy = app_settings.TOKEN_STRATEGY
    hdr_token = strategy.get_session_token(request)
    modified = request.session.modified
    empty = request.session.is_empty()
    if modified and not empty:
        new_token = strategy.create_session_token(request)
        if not hdr_token or hdr_token != new_token:
            return new_token
    return None


def authenticate_by_x_session_token(
    token: str,
) -> XSessionTokenAuthenticationResult | None:
    session = app_settings.TOKEN_STRATEGY.lookup_session(token)
    if session is None:
        return None
    user = get_session_user(session)
    return XSessionTokenAuthenticationResult(user=user, session=session)


def lookup_session(session_key: str) -> SessionBase | None:
    """
    The following results in 2 queries:

    >>> if session_store().exists(session_key):
    >>>     return session_store(session_key)
    >>> return None

    The code below avoids that.
    """
    session = session_store(session_key)
    # Trigger Django's lazy session load. Missing and expired sessions clear the
    # session key.
    session.get(SESSION_KEY)
    return session if session.session_key else None
