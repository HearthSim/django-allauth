from http import HTTPStatus
from unittest.mock import patch

from django.urls import NoReverseMatch, reverse, reverse_lazy

import pytest

from allauth.account.forms import ChangePasswordForm
from allauth.account.internal.flows.reauthenticate_by_code import (
    REAUTHENTICATION_CODE_SESSION_KEY,
)


def test_change_unusable_password_redirects_to_set(client, user, user_password):
    user.set_unusable_password()
    user.save()
    client.force_login(user)
    resp = client.get(reverse("account_change_password"))
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_set_password")


def test_set_usable_password_redirects_to_change(auth_client, user, settings):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = auth_client.get(reverse("account_set_password"))
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_change_password")


def test_set_password_requires_reauthentication(
    client, user, password_factory, settings
):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    settings.ACCOUNT_REAUTHENTICATION_METHODS = {"code"}
    user.set_unusable_password()
    user.save(update_fields=["password"])
    client.force_login(user)
    password = password_factory()

    resp = client.post(
        reverse("account_set_password"),
        {"password1": password, "password2": password},
    )

    assert resp.status_code == HTTPStatus.FOUND
    assert (
        resp["location"] == f"{reverse('account_request_reauthentication_code')}"
        "?next=%2Faccounts%2Fpassword%2Fset%2F"
    )
    user.refresh_from_db()
    assert not user.has_usable_password()

    resp = client.post(resp["location"], {"recipient": user.email})
    code = client.session[REAUTHENTICATION_CODE_SESSION_KEY]["code"]
    resp = client.post(resp["location"], {"code": code})

    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_change_password")
    user.refresh_from_db()
    assert user.check_password(password)


@pytest.mark.parametrize(
    "logout,next_url,redirect_chain",
    [
        (False, "", [(reverse_lazy("account_change_password"), HTTPStatus.FOUND)]),
        (False, "/foo", [("/foo", HTTPStatus.FOUND)]),
        (
            True,
            "",
            [
                (reverse_lazy("account_change_password"), HTTPStatus.FOUND),
                (
                    "/accounts/login/?next=/accounts/password/change/",
                    HTTPStatus.FOUND,
                ),
            ],
        ),
        (True, "/foo", [("/foo", HTTPStatus.FOUND)]),
    ],
)
def test_set_password(
    client, user, next_url, password_factory, logout, settings, redirect_chain
):
    settings.ACCOUNT_LOGOUT_ON_PASSWORD_CHANGE = logout
    user.set_unusable_password()
    user.save()
    client.force_login(user)
    password = password_factory()
    data = {"password1": password, "password2": password}
    if next_url:
        data["next"] = next_url
    resp = client.post(
        reverse("account_set_password"),
        data,
        follow=True,
    )
    assert resp.redirect_chain == redirect_chain


@pytest.mark.parametrize(
    "logout,next_url,redirect_chain",
    [
        (False, "", [(reverse_lazy("account_change_password"), HTTPStatus.FOUND)]),
        (False, "/foo", [("/foo", HTTPStatus.FOUND)]),
        (
            True,
            "",
            [
                (reverse_lazy("account_change_password"), HTTPStatus.FOUND),
                (
                    "/accounts/login/?next=/accounts/password/change/",
                    HTTPStatus.FOUND,
                ),
            ],
        ),
        (True, "/foo", [("/foo", HTTPStatus.FOUND)]),
    ],
)
def test_change_password(
    auth_client,
    user,
    user_password,
    next_url,
    password_factory,
    logout,
    settings,
    redirect_chain,
    mailoutbox,
):
    settings.ACCOUNT_LOGOUT_ON_PASSWORD_CHANGE = logout
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    password = password_factory()
    data = {"oldpassword": user_password, "password1": password, "password2": password}
    if next_url:
        data["next"] = next_url
    resp = auth_client.post(
        reverse("account_change_password"),
        data,
        follow=True,
    )
    assert resp.redirect_chain == redirect_chain
    assert len(mailoutbox) == 1
    assert "Your password has been changed" in mailoutbox[0].body


def test_change_password_forgotten_link_not_present(client, db):
    with patch("allauth.account.fields.reverse") as reverse_mock:
        reverse_mock.side_effect = NoReverseMatch
        form = ChangePasswordForm()
        assert form.fields["oldpassword"].help_text == ""


def test_change_password_forgotten_link_present(client, db):
    form = ChangePasswordForm()
    assert (
        form.fields["oldpassword"].help_text
        == '<a href="/accounts/password/reset/">Forgot your password?</a>'
    )
