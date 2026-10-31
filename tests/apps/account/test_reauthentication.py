import time
from http import HTTPStatus
from unittest.mock import ANY

from django.urls import reverse

import pytest
from pytest_django.asserts import assertTemplateUsed

from allauth import app_settings as allauth_settings
from allauth.account.adapter import DefaultAccountAdapter, get_adapter
from allauth.account.authentication import get_authentication_records
from allauth.account.decorators import reauthentication_required
from allauth.account.internal.flows.reauthenticate_by_code import (
    REAUTHENTICATION_CODE_SESSION_KEY,
)
from allauth.account.models import EmailAddress
from allauth.core.exceptions import ReauthenticationRequired


class ReauthenticationRequiredAdapter(DefaultAccountAdapter):
    def is_reauthentication_required(self, *, app, **kwargs):
        return app == "allauth.account"


def request_reauthentication_code(client, recipient, next_url=None):
    data = {"recipient": recipient}
    if next_url:
        data["next"] = next_url
    resp = client.post(reverse("account_request_reauthentication_code"), data=data)
    assert resp.status_code == HTTPStatus.FOUND
    state = client.session[REAUTHENTICATION_CODE_SESSION_KEY]
    return resp, state["code"]


@pytest.mark.parametrize(
    "with_totp,with_password,expected_method_urlnames",
    [
        (
            False,
            True,
            ["account_reauthenticate", "account_request_reauthentication_code"],
        ),
        (
            True,
            True,
            [
                "account_reauthenticate",
                "account_request_reauthentication_code",
                "mfa_reauthenticate",
            ],
        ),
        (
            True,
            False,
            ["account_request_reauthentication_code", "mfa_reauthenticate"],
        ),
    ],
)
def test_user_with_mfa_only(
    user_factory, with_totp, with_password, expected_method_urlnames, client
):
    if not allauth_settings.MFA_ENABLED and with_totp:
        return
    user = user_factory(with_totp=with_totp, password=None if with_password else "!")
    assert user.has_usable_password() == with_password
    client.force_login(user)
    methods = get_adapter().get_reauthentication_methods(user)
    assert len(methods) == len(expected_method_urlnames)
    assert {m["url"] for m in methods} == set(map(reverse, expected_method_urlnames))
    for urlname in [
        "account_reauthenticate",
        "account_request_reauthentication_code",
        "mfa_reauthenticate",
    ]:
        if urlname == "mfa_reauthenticate" and not allauth_settings.MFA_ENABLED:
            continue
        resp = client.get(f"{reverse(urlname)}?next=/foo")
        if urlname in expected_method_urlnames:
            assert resp.status_code == HTTPStatus.OK
        else:
            assert resp.status_code == HTTPStatus.FOUND
            assert "next=%2Ffoo" in resp["location"]


def test_reauthentication(settings, auth_client, user, user_password):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "john3@example.org"},
    )
    assert resp["location"].startswith(reverse("account_reauthenticate"))
    resp = auth_client.get(reverse("account_reauthenticate"))
    assertTemplateUsed(resp, "account/reauthenticate.html")
    resp = auth_client.post(
        reverse("account_reauthenticate"), data={"password": user_password}
    )
    assert resp.status_code == HTTPStatus.FOUND
    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "john3@example.org"},
    )
    assert resp["location"].startswith(reverse("account_email"))
    methods = get_authentication_records(resp.wsgi_request, user)
    assert methods[-1] == {
        "method": "password",
        "at": ANY,
        "reauthenticated": True,
    }


@pytest.mark.parametrize("recipient_type", ["email", "phone"])
def test_reauthentication_by_code(
    recipient_type,
    auth_client,
    user_with_phone,
    phone,
    mailoutbox,
    sms_outbox,
):
    recipient = user_with_phone.email if recipient_type == "email" else phone
    request_url = reverse("account_request_reauthentication_code")
    confirm_url = reverse("account_confirm_reauthentication_code")

    resp = auth_client.get(f"{request_url}?next=/foo")
    assertTemplateUsed(resp, "account/request_reauthentication_code.html")

    resp, code = request_reauthentication_code(auth_client, recipient, next_url="/foo")
    assert resp["location"] == f"{confirm_url}?next=%2Ffoo"
    if recipient_type == "email":
        assert code in mailoutbox[-1].body
    else:
        assert sms_outbox[-1] == {
            "code": code,
            "phone": phone,
            "user_id": user_with_phone.pk,
        }

    resp = auth_client.get(resp["location"])
    assertTemplateUsed(resp, "account/confirm_reauthentication_code.html")
    assert recipient.encode() in resp.content

    resp = auth_client.post(confirm_url, data={"code": code, "next": "/foo"})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == "/foo"
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.session
    assert get_authentication_records(resp.wsgi_request, user_with_phone)[-1] == {
        "method": "code",
        "at": ANY,
        recipient_type: recipient,
        "reauthenticated": True,
    }


def test_confirm_reauthentication_code_without_pending_process(auth_client):
    resp = auth_client.get(
        f"{reverse('account_confirm_reauthentication_code')}?next=/foo"
    )

    assert resp.status_code == HTTPStatus.FOUND
    assert (
        resp["location"]
        == f"{reverse('account_request_reauthentication_code')}?next=%2Ffoo"
    )


def test_reauthentication_code_max_attempts(settings, auth_client, user):
    settings.ACCOUNT_LOGIN_BY_CODE_MAX_ATTEMPTS = 2
    _, code = request_reauthentication_code(auth_client, user.email, next_url="/foo")
    confirm_url = reverse("account_confirm_reauthentication_code")
    data = {"code": f"wrong-{code}", "next": "/foo"}

    resp = auth_client.post(confirm_url, data=data)
    assert resp.status_code == HTTPStatus.OK
    assertTemplateUsed(resp, "account/confirm_reauthentication_code.html")
    assert REAUTHENTICATION_CODE_SESSION_KEY in auth_client.session

    resp = auth_client.post(confirm_url, data=data)
    assert resp.status_code == HTTPStatus.FOUND
    assert (
        resp["location"]
        == f"{reverse('account_request_reauthentication_code')}?next=%2Ffoo"
    )
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.session


def test_reauthentication_code_expired(settings, auth_client, user):
    settings.ACCOUNT_LOGIN_BY_CODE_TIMEOUT = 1
    request_reauthentication_code(auth_client, user.email)
    session = auth_client.session
    state = session[REAUTHENTICATION_CODE_SESSION_KEY]
    state["at"] = time.time() - 2
    session[REAUTHENTICATION_CODE_SESSION_KEY] = state
    session.save()

    resp = auth_client.get(reverse("account_confirm_reauthentication_code"))

    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_request_reauthentication_code")
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.session


def test_resend_reauthentication_code(settings, auth_client, user, mailoutbox):
    settings.ACCOUNT_LOGIN_BY_CODE_SUPPORTS_RESEND = 1
    _, code = request_reauthentication_code(auth_client, user.email, next_url="/foo")
    confirm_url = reverse("account_confirm_reauthentication_code")

    resp = auth_client.post(confirm_url, data={"action": "resend", "next": "/foo"})

    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == f"{confirm_url}?next=%2Ffoo"
    assert auth_client.session[REAUTHENTICATION_CODE_SESSION_KEY]["code"] != code
    assert len(mailoutbox) == 2


def test_request_reauthentication_code_validates_recipient(
    auth_client, user, mailoutbox
):
    unverified_email = "unverified@example.org"
    EmailAddress.objects.create(user=user, email=unverified_email, verified=False)

    resp = auth_client.post(
        reverse("account_request_reauthentication_code"),
        data={"recipient": unverified_email},
    )

    assert resp.status_code == HTTPStatus.OK
    assert "recipient" in resp.context["form"].errors
    assert not mailoutbox
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.session


@pytest.mark.parametrize("recipient_type", ["email", "phone"])
def test_request_reauthentication_code_rate_limit(
    recipient_type,
    settings,
    enable_cache,
    auth_client,
    user_with_phone,
    phone,
    mailoutbox,
    sms_outbox,
):
    settings.ACCOUNT_RATE_LIMITS = {"request_login_code": "1/m/key"}
    recipient = user_with_phone.email if recipient_type == "email" else phone

    resp = auth_client.post(
        reverse("account_request_reauthentication_code"),
        data={"recipient": recipient},
    )
    assert resp.status_code == HTTPStatus.FOUND

    resp = auth_client.post(
        reverse("account_request_reauthentication_code"),
        data={"recipient": recipient},
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.context["form"].errors == {
        "recipient": ["Too many failed login attempts. Try again later."]
    }
    assert len(mailoutbox if recipient_type == "email" else sms_outbox) == 1


def test_reauthentication_required_decorator_is_enabled_by_default(settings, rf, user):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = False
    request = rf.post("/")
    request.user = user
    request.session = {}

    @reauthentication_required
    def view(request):
        raise AssertionError("The protected view must not be called")

    with pytest.raises(ReauthenticationRequired):
        view(request)


def test_adapter_can_require_reauthentication(settings, auth_client):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = False
    settings.ACCOUNT_ADAPTER = (
        "tests.apps.account.test_reauthentication." "ReauthenticationRequiredAdapter"
    )

    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "reauthenticate@example.org"},
    )

    assert not EmailAddress.objects.filter(email="reauthenticate@example.org").exists()
    assert resp["location"].startswith(reverse("account_reauthenticate"))
