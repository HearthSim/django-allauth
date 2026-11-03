from __future__ import annotations

import time
from typing import Any

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponseRedirect
from django.urls import reverse
from django.utils.http import urlencode

from allauth import app_settings as allauth_settings
from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.internal import phonekit
from allauth.account.internal.flows.login import (
    get_authentication_records,
    record_authentication,
)
from allauth.account.models import EmailAddress
from allauth.core.exceptions import ReauthenticationRequired
from allauth.core.internal.httpkit import (
    authenticated_user,
    deserialize_request,
    serialize_request,
)
from allauth.core.internal.urlkit import script_aware_resolve
from allauth.utils import import_callable


STATE_SESSION_KEY = "account_reauthentication_state"


def raise_if_reauthentication_method_not_enabled(method: str) -> None:
    if method not in app_settings.REAUTHENTICATION_METHODS:
        raise PermissionDenied


def get_reauthentication_code_recipients(
    user: AbstractBaseUser,
) -> list[dict[str, str]]:
    recipients = [
        {"email": email}
        for email in EmailAddress.objects.filter(user_id=user.pk, verified=True)
        .values_list("email", flat=True)
        .order_by("email")
    ]
    phone = phonekit.get_verified_phone(user)
    if phone is not None:
        recipients.append({"phone": phone})
    return recipients


def reauthenticate_by_password(request: HttpRequest) -> None:
    raise_if_reauthentication_method_not_enabled("password")
    record_authentication(
        request, authenticated_user(request), method="password", reauthenticated=True
    )


def stash_and_reauthenticate(
    request: HttpRequest, state: dict, callback: str
) -> HttpResponseRedirect:
    methods = get_adapter().get_reauthentication_methods(request.user)
    if not methods:
        raise PermissionDenied("Reauthentication not available")
    request.session[STATE_SESSION_KEY] = {
        "state": state,
        "callback": callback,
    }
    return HttpResponseRedirect(methods[0]["url"])


def suspend_request(request: HttpRequest, redirect_to: str) -> HttpResponseRedirect:
    path = request.get_full_path()
    if request.method == "POST":
        request.session[STATE_SESSION_KEY] = {"request": serialize_request(request)}
    return HttpResponseRedirect(
        f"{redirect_to}?{urlencode({REDIRECT_FIELD_NAME: path})}"
    )


def resume_request(request: HttpRequest) -> HttpResponseRedirect | None:
    from allauth.account.utils import get_next_redirect_url

    state = request.session.pop(STATE_SESSION_KEY, None)
    if state and "callback" in state:
        callback = import_callable(state["callback"])
        return callback(request, state["state"])

    url = get_next_redirect_url(request, REDIRECT_FIELD_NAME)
    if not url:
        return None
    if state and "request" in state:
        suspended_request = deserialize_request(state["request"], request)
        if suspended_request.path == url:
            resolved = script_aware_resolve(suspended_request.path)
            return resolved.func(suspended_request, *resolved.args, **resolved.kwargs)
    return HttpResponseRedirect(url)


def is_reauthentication_required(request: HttpRequest, *, app: str) -> bool:
    if not request.user.is_authenticated:
        return True
    if not get_adapter().is_reauthentication_required(app=app):
        return False
    return not did_recently_reauthenticate(request)


def raise_if_reauthentication_required(request: HttpRequest, *, app: str) -> None:
    if is_reauthentication_required(
        request,
        app=app,
    ):
        raise ReauthenticationRequired()


def did_recently_reauthenticate(request: HttpRequest) -> bool:
    if request.user.is_anonymous:
        return False
    if not get_reauthentication_flows(request.user):
        return False
    methods = get_authentication_records(request, request.user)
    methods = [
        m
        for m in methods
        if m.get("reauthenticated")
        and m.get("method") in app_settings.REAUTHENTICATION_METHODS
    ]
    if not methods:
        return False
    authenticated_at = methods[-1]["at"]
    return time.time() - authenticated_at < app_settings.REAUTHENTICATION_TIMEOUT


def get_reauthentication_flows(user: AbstractBaseUser) -> list[dict[str, Any]]:
    enabled_methods = app_settings.REAUTHENTICATION_METHODS
    ret: list[dict[str, Any]] = []
    if not user.is_authenticated:
        return ret
    if user.has_usable_password() and "password" in enabled_methods:
        entry: dict[str, Any] = {
            "id": "reauthenticate",
        }
        ret.append(entry)
    recipients = []
    if not allauth_settings.SOCIALACCOUNT_ONLY and "code" in enabled_methods:
        recipients = get_reauthentication_code_recipients(user)
    if recipients:
        entry = {
            "id": "reauthenticate_by_code",
            "recipients": recipients,
        }
        ret.append(entry)
    if allauth_settings.MFA_ENABLED and "mfa" in enabled_methods:
        from allauth.mfa.models import Authenticator
        from allauth.mfa.utils import is_mfa_enabled

        types = []
        for typ in Authenticator.Type:
            if is_mfa_enabled(user, types=[typ]):
                types.append(typ)
        if types:
            ret.append({"id": "mfa_reauthenticate", "types": types})
    return ret


def is_reauthentication_method(request: HttpRequest, method: dict) -> bool:
    """
    Is this request on a path that is part of the reauthentication method?
    """
    urls = [method["url"]]
    if method.get("id") == "reauthenticate_by_code":
        urls.append(reverse("account_confirm_reauthentication_code"))
    return any(url == request.path for url in urls)
