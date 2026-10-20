from __future__ import annotations

from django.http import HttpRequest, HttpResponseBadRequest

from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.recharge.views import (
    STORE_DOMAIN_PARAMS,
    RechargeOAuth2Adapter,
    get_store_domain,
)


class RechargeAccount(ProviderAccount):
    def to_str(self):
        # The base implementation ranks `email` above `name`, but the account
        # represents a store, so the store name is more recognizable than the
        # store's contact email address.
        if name := self.account.extra_data.get("name"):
            return name
        return super().to_str()


class RechargeProvider(OAuth2Provider):
    id = "recharge"
    name = "Recharge"
    account_class = RechargeAccount
    oauth2_adapter_class = RechargeOAuth2Adapter

    def extract_uid(self, data: dict) -> str:
        return str(data["store"]["id"])

    def extract_common_fields(self, data: dict) -> dict:
        ret: dict = {}
        store = self.extract_extra_data(data)
        if email := store.get("email"):
            ret["email"] = email
        if name := store.get("name"):
            ret["name"] = name
        return ret

    def extract_extra_data(self, data: dict) -> dict:
        return data["store"]

    def get_auth_params_from_request(self, request: HttpRequest, action):
        ret = super().get_auth_params_from_request(request, action)
        for param in STORE_DOMAIN_PARAMS:
            value = request.GET.get(param)
            if value:
                ret[param] = value
        return ret

    def redirect(
        self, request: HttpRequest, process, next_url=None, data=None, **kwargs
    ):
        # Recharge does not round-trip a `state` parameter, so stash the store
        # domain the install was started for; the callback view verifies it
        # against the domain echoed back by Recharge (a one-time binding
        # standing in for the state check).
        auth_params = kwargs.get("auth_params")
        if auth_params is None:
            auth_params = self.get_auth_params()
            kwargs["auth_params"] = auth_params
        store_domain = get_store_domain(auth_params)
        if not store_domain:
            # Without it, Recharge cannot identify the store the app is to be
            # installed on, and the callback could not be bound to the store
            # the flow was started for.
            raise ImmediateHttpResponse(
                HttpResponseBadRequest("Missing store domain parameter")
            )
        kwargs["store_domain"] = store_domain
        return super().redirect(
            request, process, next_url=next_url, data=data, **kwargs
        )


provider_classes = [RechargeProvider]
providers.registry.register(RechargeProvider)
