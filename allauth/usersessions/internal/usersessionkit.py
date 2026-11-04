from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.http import HttpRequest

from allauth import app_settings as allauth_settings
from allauth.usersessions import app_settings


if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.contrib.auth.models import AnonymousUser
    from django.contrib.sessions.backends.base import SessionBase


def track_activity(
    request: HttpRequest | None,
    *,
    user: AbstractBaseUser | AnonymousUser | None,
    session: SessionBase | None,
) -> None:
    if (
        request is None
        or not allauth_settings.USERSESSIONS_ENABLED
        or not app_settings.TRACK_ACTIVITY
    ):
        return
    if session is None:
        return
    if user is None or not user.is_authenticated:
        return
    if not session.session_key:
        return
    tracked: set[str] = getattr(request, "_allauth_usersessions_tracked", set())
    if session.session_key in tracked:
        return

    from allauth.usersessions.models import UserSession

    UserSession.objects.create_from_request(
        request, user=cast("AbstractBaseUser", user), session=session
    )
    tracked.add(session.session_key)
    setattr(request, "_allauth_usersessions_tracked", tracked)
