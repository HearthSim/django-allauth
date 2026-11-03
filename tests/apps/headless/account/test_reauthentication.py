import time
from http import HTTPStatus

from django.urls import NoReverseMatch

import pytest

from allauth.account.internal.flows.reauthenticate_by_code import (
    REAUTHENTICATION_CODE_SESSION_KEY,
)
from allauth.account.internal.flows.reauthentication import get_reauthentication_flows
from allauth.account.models import EmailAddress
from allauth.headless.constants import Flow


def get_last_email_code(mailoutbox):
    return [line for line in mailoutbox[-1].body.splitlines() if len(line) == 9][0]


def test_reauthenticate(
    auth_client, user, user_password, headless_reverse, headless_client
):
    resp = auth_client.get(
        headless_reverse("headless:account:current_session"),
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    method_count = len(data["data"]["methods"])

    resp = auth_client.post(
        headless_reverse("headless:account:reauthenticate"),
        data={
            "password": user_password,
        },
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK

    resp = auth_client.get(
        headless_reverse("headless:account:current_session"),
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert len(data["data"]["methods"]) == method_count + 1
    last_method = data["data"]["methods"][-1]
    assert last_method["method"] == "password"


@pytest.mark.parametrize(
    ("method", "url_name"),
    [
        ("password", "headless:account:reauthenticate"),
        ("code", "headless:account:request_reauthentication_code"),
        ("code", "headless:account:confirm_reauthentication_code"),
        ("code", "headless:account:resend_reauthentication_code"),
    ],
)
def test_reauthentication_method_disabled(
    settings, auth_client, headless_reverse, method, url_name
):
    settings.ACCOUNT_REAUTHENTICATION_METHODS = {"password", "code", "mfa"} - {method}
    resp = auth_client.post(
        headless_reverse(url_name),
        data={},
        content_type="application/json",
    )

    assert resp.status_code == HTTPStatus.FORBIDDEN
    assert resp["content-type"] == "application/json"
    assert resp.json()["status"] == HTTPStatus.FORBIDDEN


def test_disabled_reauthentication_code_not_advertised_as_pending(
    settings, auth_client, user, headless_reverse, email_factory
):
    resp = auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data={"email": user.email},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    assert REAUTHENTICATION_CODE_SESSION_KEY in auth_client.headless_session()

    settings.ACCOUNT_REAUTHENTICATION_METHODS = {"password"}
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = auth_client.post(
        headless_reverse("headless:account:manage_email"),
        data={"email": email_factory()},
        content_type="application/json",
    )

    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json()["data"]["flows"] == [{"id": Flow.REAUTHENTICATE}]


def test_reauthenticate_rate_limit(
    auth_client,
    user,
    user_password,
    headless_reverse,
    headless_client,
    settings,
    enable_cache,
):
    settings.ACCOUNT_RATE_LIMITS = {"reauthenticate": "1/m/ip"}
    for attempt in range(4):
        resp = auth_client.post(
            headless_reverse("headless:account:reauthenticate"),
            data={
                "password": user_password,
            },
            content_type="application/json",
        )
        expected_status = HTTPStatus.TOO_MANY_REQUESTS if attempt else HTTPStatus.OK
        assert resp.status_code == expected_status
        assert resp.json()["status"] == expected_status


def test_reauthenticate_by_email_code(auth_client, user, headless_reverse, mailoutbox):
    resp = auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data={"email": user.email},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK

    resp = auth_client.post(
        headless_reverse("headless:account:confirm_reauthentication_code"),
        data={"code": get_last_email_code(mailoutbox)},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    method = resp.json()["data"]["methods"][-1]
    assert method["method"] == "code"
    assert method["email"] == user.email
    assert method["reauthenticated"] is True

    resp = auth_client.post(
        headless_reverse("headless:account:confirm_reauthentication_code"),
        data={"code": get_last_email_code(mailoutbox)},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.CONFLICT


def test_reauthenticate_by_phone_code(
    auth_client, user_with_phone, phone, headless_reverse, sms_outbox
):
    resp = auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data={"phone": phone},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK

    resp = auth_client.post(
        headless_reverse("headless:account:confirm_reauthentication_code"),
        data={"code": sms_outbox[-1]["code"]},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    method = resp.json()["data"]["methods"][-1]
    assert method["method"] == "code"
    assert method["phone"] == phone
    assert method["reauthenticated"] is True


@pytest.mark.parametrize("recipient_type", ["email", "phone"])
def test_request_reauthentication_code_rate_limit(
    recipient_type,
    settings,
    enable_cache,
    auth_client,
    user_with_phone,
    phone,
    headless_reverse,
    mailoutbox,
    sms_outbox,
):
    settings.ACCOUNT_RATE_LIMITS = {"request_login_code": "1/m/key"}
    recipient = user_with_phone.email if recipient_type == "email" else phone
    data = {recipient_type: recipient}

    resp = auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data=data,
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK

    resp = auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data=data,
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json()["errors"] == [
        {
            "code": "too_many_login_attempts",
            "message": "Too many failed login attempts. Try again later.",
            "param": recipient_type,
        }
    ]
    assert len(mailoutbox if recipient_type == "email" else sms_outbox) == 1


def test_request_reauthentication_code_validates_recipient(
    auth_client,
    user_with_phone,
    phone,
    phone_factory,
    headless_reverse,
    mailoutbox,
    sms_outbox,
):
    unverified_email = "unverified@example.org"
    EmailAddress.objects.create(
        user=user_with_phone, email=unverified_email, verified=False
    )
    cases = [
        ({"email": unverified_email}, "email", "unknown_email"),
        ({"phone": phone_factory()}, "phone", "unknown_phone"),
        (
            {"email": user_with_phone.email, "phone": phone},
            None,
            "select_only_one",
        ),
        ({}, None, "required"),
    ]
    for data, param, code in cases:
        resp = auth_client.post(
            headless_reverse("headless:account:request_reauthentication_code"),
            data=data,
            content_type="application/json",
        )
        assert resp.status_code == HTTPStatus.BAD_REQUEST
        error = resp.json()["errors"][0]
        assert error["code"] == code
        assert error.get("param") == param

    assert not mailoutbox
    assert not sms_outbox
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.headless_session()


def test_reauthentication_code_max_attempts(
    auth_client, user, headless_reverse, settings
):
    settings.ACCOUNT_LOGIN_BY_CODE_MAX_ATTEMPTS = 1
    auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data={"email": user.email},
        content_type="application/json",
    )
    resp = auth_client.post(
        headless_reverse("headless:account:confirm_reauthentication_code"),
        data={"code": "wrong"},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.headless_session()

    resp = auth_client.post(
        headless_reverse("headless:account:confirm_reauthentication_code"),
        data={"code": "wrong"},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.CONFLICT


def test_reauthentication_code_expired(auth_client, user, headless_reverse, settings):
    settings.ACCOUNT_LOGIN_BY_CODE_TIMEOUT = 1
    auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data={"email": user.email},
        content_type="application/json",
    )
    session = auth_client.headless_session()
    state = session[REAUTHENTICATION_CODE_SESSION_KEY]
    state["at"] = time.time() - 2
    session[REAUTHENTICATION_CODE_SESSION_KEY] = state
    session.save()

    resp = auth_client.post(
        headless_reverse("headless:account:confirm_reauthentication_code"),
        data={"code": state["code"]},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.CONFLICT
    assert REAUTHENTICATION_CODE_SESSION_KEY not in auth_client.headless_session()


def test_resend_reauthentication_code(
    auth_client, user, headless_reverse, mailoutbox, settings
):
    settings.ACCOUNT_LOGIN_BY_CODE_SUPPORTS_RESEND = 1
    auth_client.post(
        headless_reverse("headless:account:request_reauthentication_code"),
        data={"email": user.email},
        content_type="application/json",
    )
    code = get_last_email_code(mailoutbox)

    resp = auth_client.post(
        headless_reverse("headless:account:resend_reauthentication_code")
    )
    assert resp.status_code == HTTPStatus.OK
    assert get_last_email_code(mailoutbox) != code

    resp = auth_client.post(
        headless_reverse("headless:account:resend_reauthentication_code")
    )
    assert resp.status_code == HTTPStatus.CONFLICT


def test_reauthentication_code_socialaccount_only(
    auth_client, user, headless_reverse, settings_impacting_urls
):
    with settings_impacting_urls(SOCIALACCOUNT_ONLY=True):
        with pytest.raises(NoReverseMatch):
            headless_reverse("headless:account:request_reauthentication_code")

        flows = get_reauthentication_flows(user)
        assert all(flow["id"] != Flow.REAUTHENTICATE_BY_CODE for flow in flows)
