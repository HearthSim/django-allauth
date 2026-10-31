from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.forms import Form
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import (
    ConfirmReauthenticationCodeForm,
    ReauthenticateForm,
    RequestReauthenticationCodeForm,
)
from allauth.account.internal import flows
from allauth.account.mixins import NextRedirectMixin
from allauth.account.views._authentication_by_code import (
    BaseConfirmAuthenticationCodeView,
)
from allauth.core import ratelimit
from allauth.core.internal.httpkit import authenticated_user
from allauth.core.ratelimit import RateLimited
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
        if any(
            flows.reauthentication.is_reauthentication_method(request, method)
            for method in methods
        ):
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
            if flows.reauthentication.is_reauthentication_method(self.request, method):
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


@method_decorator(login_required, name="dispatch")
class RequestReauthenticationCodeView(BaseReauthenticateView):
    template_name = (
        f"account/request_reauthentication_code.{app_settings.TEMPLATE_EXTENSION}"
    )
    form_class = RequestReauthenticationCodeForm

    def get_form_kwargs(self) -> dict:
        ret = super().get_form_kwargs()
        ret["user"] = self.request.user
        return ret

    def form_valid(self, form) -> HttpResponse:
        flows.reauthenticate_by_code.ConfirmReauthenticationCodeProcess.initiate(
            request=self.request,
            user=self.request.user,
            email=form.cleaned_data.get("email"),
            phone=form.cleaned_data.get("phone"),
        )
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_confirm_reauthentication_code"))
        )


request_reauthentication_code = RequestReauthenticationCodeView.as_view()


@method_decorator(login_required, name="dispatch")
class ConfirmReauthenticationCodeView(BaseConfirmAuthenticationCodeView):
    _process: flows.reauthenticate_by_code.ConfirmReauthenticationCodeProcess
    template_name = (
        f"account/confirm_reauthentication_code.{app_settings.TEMPLATE_EXTENSION}"
    )
    form_class = ConfirmReauthenticationCodeForm

    @method_decorator(never_cache)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        process = (
            flows.reauthenticate_by_code.ConfirmReauthenticationCodeProcess.resume(
                request
            )
        )
        if not process:
            return HttpResponseRedirect(
                self.passthrough_next_url(
                    reverse("account_request_reauthentication_code")
                )
            )
        self._process = process
        return super().dispatch(request, *args, **kwargs)

    def get_default_success_url(self):
        return get_adapter(self.request).get_login_redirect_url(self.request)

    def get_form_class(self):
        if self._action == "resend":
            return Form
        return get_form_class(
            app_settings.FORMS, "confirm_reauthentication_code", self.form_class
        )

    def _resend_form_valid(self, form) -> HttpResponse:
        try:
            self._process.resend()
        except RateLimited:
            adapter = get_adapter()
            adapter.add_message(
                self.request,
                messages.ERROR,
                message=adapter.error_messages["rate_limited"],
            )
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_confirm_reauthentication_code"))
        )

    def _verify_form_valid(self, form) -> HttpResponse:
        self._process.finish()
        response = flows.reauthentication.resume_request(self.request)
        if response:
            return response
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form) -> HttpResponse:
        attempts_left = self._process.record_invalid_attempt()
        if attempts_left:
            return super().form_invalid(form)
        adapter = get_adapter(self.request)
        adapter.add_message(
            self.request,
            messages.ERROR,
            message=adapter.error_messages["too_many_login_attempts"],
        )
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_request_reauthentication_code"))
        )

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        email = self._process.state.get("email")
        phone = self._process.state.get("phone")
        ret.update(
            {
                "can_resend": self._process.can_resend,
                "email": email,
                "phone": phone,
                "verify_form": ret["form"],
                "cancel_url": self.passthrough_next_url(
                    reverse("account_request_reauthentication_code")
                ),
            }
        )
        return ret


confirm_reauthentication_code = ConfirmReauthenticationCodeView.as_view()
