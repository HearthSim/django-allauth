from unittest.mock import patch

import pytest

from allauth.mfa import app_settings as mfa_app_settings
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal import auth


@pytest.mark.parametrize("cache_add_result", [False, True])
@pytest.mark.parametrize("tolerance", [0, 1])
def test_totp_code_is_claimed_atomically(
    user_with_totp, cache_add_result, tolerance, settings
):
    settings.MFA_TOTP_TOLERANCE = tolerance
    totp = Authenticator.objects.get(
        user=user_with_totp, type=Authenticator.Type.TOTP
    ).wrap()
    with (
        patch("allauth.mfa.totp.internal.auth.validate_totp_code", return_value=True),
        patch("allauth.mfa.totp.internal.auth.cache.get") as cache_get,
        patch(
            "allauth.mfa.totp.internal.auth.cache.add", return_value=cache_add_result
        ) as cache_add,
    ):
        assert totp.validate_code("123456") is cache_add_result

    cache_get.assert_not_called()
    cache_add.assert_called_once_with(
        totp._get_used_cache_key("123456"),
        "y",
        timeout=mfa_app_settings.TOTP_PERIOD * (2 * tolerance + 1),
    )


def test_validate_non_ascii_code(user_with_totp):
    totp = Authenticator.objects.get(
        user=user_with_totp, type=Authenticator.Type.TOTP
    ).wrap()
    assert not totp.validate_code("€#")


def test_totp_code_reuse_within_tolerance_window(
    user_with_totp, enable_cache, settings
):
    settings.MFA_TOTP_TOLERANCE = 1
    totp = Authenticator.objects.get(
        user=user_with_totp, type=Authenticator.Type.TOTP
    ).wrap()
    secret = auth.decrypt(totp.instance.data["secret"])
    now = 1731948631
    period = mfa_app_settings.TOTP_PERIOD
    code = auth.format_hotp_value(auth.hotp_value(secret, now // period))

    with patch("time.time", return_value=now):
        assert totp.validate_code(code)
        assert not totp.validate_code(code)

    # The code remains valid one period later, but must remain claimed.
    with patch("time.time", return_value=now + period + 1):
        assert not totp.validate_code(code)

    # Once outside the tolerance window, the code itself is no longer valid.
    with patch("time.time", return_value=now + 2 * period + 1):
        assert not totp.validate_code(code)
