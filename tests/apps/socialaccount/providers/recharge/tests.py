import requests
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from django.test import TestCase
from django.urls import reverse
from django.utils.http import urlencode

from allauth.socialaccount import app_settings
from allauth.socialaccount.providers.recharge.provider import RechargeProvider
from tests.apps.socialaccount.base import OAuth2TestsMixin
from tests.mocking import MockedResponse


class RechargeTests(OAuth2TestsMixin, TestCase):
    provider_id = RechargeProvider.id

    def setup_provider(self):
        super().setup_provider()
        # Recharge's token exchange takes no client secret, so the app is
        # configured without one.
        self.app.secret = ""
        self.app.save(update_fields=["secret"])

    def login(self, resp_mock=None, process="login", with_refresh_token=True):
        resp = self.client.post(
            reverse(f"{self.provider.id}_login")
            + "?"
            + urlencode({"process": process, "myshopify_domain": "acme.myshopify.com"})
        )
        self.assertEqual(resp.status_code, HTTPStatus.FOUND)
        p = urlparse(resp["location"])
        self.assertEqual(
            f"{p.scheme}://{p.netloc}{p.path}",
            "https://admin.rechargeapps.com/partners/app/app123id/install",
        )
        q = parse_qs(p.query)
        self.assertEqual(q["myshopify_domain"], ["acme.myshopify.com"])
        # The install URL fixes the callback URL and scopes at app
        # registration time, and the client ID is part of the URL path.
        for param in (
            "client_id",
            "redirect_uri",
            "scope",
            "response_type",
            "state",
            "code_challenge",
            "code_challenge_method",
        ):
            self.assertNotIn(param, q)

        complete_url = reverse(f"{self.provider.id}_callback")
        response_json = self.get_login_response_json(
            with_refresh_token=with_refresh_token
        )
        if isinstance(resp_mock, list):
            resp_mocks = resp_mock
        elif resp_mock is None:
            resp_mocks = []
        else:
            resp_mocks = [resp_mock]
        with self.mocked_response(
            MockedResponse(
                HTTPStatus.OK, response_json, {"content-type": "application/json"}
            ),
            *resp_mocks,
        ):
            # Recharge does not round-trip a `state` parameter to the
            # callback; only the code and the store domain are passed.
            resp = self.client.get(
                complete_url,
                {"code": "test", "myshopify_domain": "acme.myshopify.com"},
            )

            # The token exchange authenticates using only the client ID.
            for args, kwargs in requests.Session.request.call_args_list:
                data = kwargs.get("data")
                if args and args[0] == "POST" and isinstance(data, dict):
                    self.assertEqual(data.get("grant_type"), "authorization_code")
                    self.assertEqual(data.get("client_id"), "app123id")
                    self.assertNotIn("client_secret", data)
        return resp

    def get_mocked_response(self):
        return MockedResponse(
            HTTPStatus.OK,
            """{
                "store": {
                    "id": 4797,
                    "checkout_platform": "recharge",
                    "created_at": "2020-04-22T00:20:52+00:00",
                    "currency": "USD",
                    "email": "contact@acme.com",
                    "external_platform": "shopify",
                    "identifier": "acme.myshopify.com",
                    "name": "Acme",
                    "timezone": {
                        "iana_name": "America/New_York",
                        "name": "(GMT-05:00) Eastern Time (US & Canada)"
                    },
                    "updated_at": "2020-04-25T00:20:52+00:00",
                    "weight_unit": "g"
                }
            }""",
        )

    def get_expected_to_str(self):
        return "Acme"

    def test_login_requires_store_domain(self):
        """Without a store domain, Recharge cannot identify the store to
        install the app on, nor could the callback be bound to the flow."""
        resp = self.client.post(
            reverse(f"{self.provider.id}_login") + "?" + urlencode({"process": "login"})
        )
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)

    def test_callback_rejects_store_domain_mismatch(self):
        """Recharge does not round-trip a `state` parameter; the store domain
        echoed on the callback is the one-time binding to the login that
        initiated the flow, so a callback for a different (or missing) store
        domain must not complete the login."""
        complete_url = reverse(f"{self.provider.id}_callback")
        for params in (
            {"code": "test", "myshopify_domain": "evil.myshopify.com"},
            {"code": "test"},
        ):
            with self.subTest(params=params):
                self.client.post(
                    reverse(f"{self.provider.id}_login")
                    + "?"
                    + urlencode(
                        {
                            "process": "login",
                            "myshopify_domain": "acme.myshopify.com",
                        }
                    )
                )
                resp = self.client.get(complete_url, params)
                self.assertTemplateUsed(resp, "socialaccount/authentication_error.html")

    def test_only_store_domain_reaches_install_url(self):
        """PKCE parameters and configured AUTH_PARAMS must not leak onto the
        install URL -- it only takes the store-domain parameter."""
        provider_settings = app_settings.PROVIDERS.get(self.app.provider, {}).copy()
        provider_settings["AUTH_PARAMS"] = {"foo": "bar"}
        provider_settings["OAUTH_PKCE_ENABLED"] = True
        with self.settings(
            SOCIALACCOUNT_PROVIDERS={self.app.provider: provider_settings}
        ):
            resp = self.client.post(
                reverse(f"{self.provider.id}_login")
                + "?"
                + urlencode(
                    {"process": "login", "myshopify_domain": "acme.myshopify.com"}
                )
            )
        self.assertEqual(resp.status_code, HTTPStatus.FOUND)
        q = parse_qs(urlparse(resp["location"]).query)
        self.assertEqual(q, {"myshopify_domain": ["acme.myshopify.com"]})
