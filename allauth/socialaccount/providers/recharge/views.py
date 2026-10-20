from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.utils.http import urlencode

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.helpers import render_authentication_error
from allauth.socialaccount.models import SocialToken
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)


RECHARGE_API_VERSION = "2021-11"

# The parameters carrying the store domain on the install URL, one per
# ecommerce platform Recharge integrates with.
STORE_DOMAIN_PARAMS = ("myshopify_domain", "mybigcommerce_domain", "shop_domain")


def get_store_domain(params) -> str | None:
    for param in STORE_DOMAIN_PARAMS:
        value = params.get(param)
        if value:
            return value
    return None


class RechargeOAuth2Client(OAuth2Client):
    """
    Recharge's token endpoint authenticates using only the ``client_id``;
    there is no ``client_secret`` involved in the token exchange, so the app
    is to be configured with an empty secret.
    """

    def get_redirect_url(self, authorization_url, scope, extra_params) -> str:
        # The install URL does not take ``redirect_uri``, ``scope``,
        # ``response_type`` or ``state`` parameters -- the callback URL and
        # scopes are fixed when the partner app is registered, and the
        # ``client_id`` is part of the URL path. Only the store-domain
        # parameter is passed along; anything else that ends up in the extra
        # parameters (PKCE challenge, configured ``AUTH_PARAMS``) is dropped.
        params = {k: v for k, v in extra_params.items() if k in STORE_DOMAIN_PARAMS}
        if params:
            return f"{authorization_url}?{urlencode(params)}"
        return authorization_url


class RechargeOAuth2Adapter(OAuth2Adapter):
    provider_id = "recharge"
    client_class = RechargeOAuth2Client
    # Recharge does not round-trip a `state` parameter to the callback. From
    # https://docs.getrecharge.com/docs/partner-apps:
    #
    #   "Due to the nature of logging in through the Shopify iframe, the
    #   state parameter used by many Oauth flows that protects against
    #   cross-site request forgery will not work. We are currently working
    #   on a mitigation strategy."
    #
    # So, the state cannot be looked up by ID and the most recently stashed
    # state is used instead, bound to the store domain the login was started
    # for (see `RechargeOAuth2CallbackView`).
    supports_state = False

    access_token_url = "https://www.admin.rechargeapps.com/oauth/token"  # nosec
    store_url = "https://api.rechargeapps.com/store"

    @property
    def authorize_url(self):
        client_id = self.get_provider().app.client_id
        return f"https://admin.rechargeapps.com/partners/app/{client_id}/install"

    def complete_login(self, request, app, token: SocialToken, **kwargs):
        # The ``/token_information`` endpoint does not identify the store the
        # app was installed on, so the ``/store`` resource (``read_store``
        # scope) is used to obtain a stable store identifier.
        with get_adapter().get_requests_session() as sess:
            r = sess.get(
                self.store_url,
                headers={
                    "X-Recharge-Access-Token": token.token,
                    "X-Recharge-Version": RECHARGE_API_VERSION,
                },
            )
            r.raise_for_status()
            extra_data = r.json()
        return self.get_provider().sociallogin_from_response(request, extra_data)


class RechargeOAuth2CallbackView(OAuth2CallbackView):
    def _get_state(self, request: HttpRequest, provider):
        state, resp = super()._get_state(request, provider)
        if state is not None:
            # Recharge does not round-trip a `state` parameter, so the store
            # domain echoed on the callback is the one-time binding between
            # this callback and the login that initiated it. Reject callbacks
            # for a different store than the state was stashed for.
            expected_domain = state.get("store_domain")
            if expected_domain and expected_domain != get_store_domain(request.GET):
                return None, render_authentication_error(
                    request,
                    provider,
                    exception=PermissionDenied("Store domain mismatch"),
                    extra_context={"state": state, "callback_view": self},
                )
        return state, resp


oauth2_login = OAuth2LoginView.adapter_view(RechargeOAuth2Adapter)
oauth2_callback = RechargeOAuth2CallbackView.adapter_view(RechargeOAuth2Adapter)
