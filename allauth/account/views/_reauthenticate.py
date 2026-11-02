from __future__ import annotations

from typing import Any

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.utils.decorators import method_decorator
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import ReauthenticateForm
from allauth.account.internal import flows
from allauth.account.mixins import NextRedirectMixin
from allauth.core import ratelimit
from allauth.core.internal.httpkit import authenticated_user
from allauth.utils import get_form_class


class BaseReauthenticateView(NextRedirectMixin, FormView):
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        resp = self._check_reauthentication_method_available(request)
        if resp:
            return resp
        resp = self._check_ratelimit(request)
        if resp:
            return resp
        return super().dispatch(request, *args, **kwargs)

    def _check_ratelimit(self, request: HttpRequest):
        return ratelimit.consume_or_429(
            self.request,
            action="reauthenticate",
            user=self.request.user,
        )

    def _check_reauthentication_method_available(self, request: HttpRequest):
        methods = get_adapter().get_reauthentication_methods(
            authenticated_user(self.request)
        )
        if any([m["url"] == request.path for m in methods]):
            # Method is available
            return None
        if not methods:
            # Reauthentication not available
            raise PermissionDenied("Reauthentication not available")
        url = self.passthrough_next_url(methods[0]["url"])
        return HttpResponseRedirect(url)

    def get_default_success_url(self):
        url = get_adapter(self.request).get_login_redirect_url(self.request)
        return url

    def form_valid(self, form) -> HttpResponse:
        response = flows.reauthentication.resume_request(self.request)
        if response:
            return response
        return super().form_valid(form)

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(
            {
                "reauthentication_alternatives": self.get_reauthentication_alternatives(),
            }
        )
        return ret

    def get_reauthentication_alternatives(self):
        methods = get_adapter().get_reauthentication_methods(self.request.user)
        alts = []
        for method in methods:
            alt = dict(method)
            if self.request.path == alt["url"]:
                continue
            alt["url"] = self.passthrough_next_url(alt["url"])
            alts.append(alt)
        alts = sorted(alts, key=lambda alt: alt["description"])
        return alts


@method_decorator(login_required, name="dispatch")
class ReauthenticateView(BaseReauthenticateView):
    form_class = ReauthenticateForm
    template_name = f"account/reauthenticate.{app_settings.TEMPLATE_EXTENSION}"

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "reauthenticate", self.form_class)

    def get_form_kwargs(self) -> dict:
        ret = super().get_form_kwargs()
        ret["user"] = self.request.user
        return ret

    def form_valid(self, form) -> HttpResponse:
        flows.reauthentication.reauthenticate_by_password(self.request)
        return super().form_valid(form)


reauthenticate = ReauthenticateView.as_view()
