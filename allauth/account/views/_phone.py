from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.forms import Form
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.views.decorators.cache import never_cache
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import ChangePhoneForm, VerifyPhoneForm
from allauth.account.internal import flows
from allauth.account.internal.decorators import login_not_required, login_stage_required
from allauth.account.internal.templatekit import get_entrance_context_data
from allauth.account.mixins import NextRedirectMixin
from allauth.account.stages import PhoneVerificationStage
from allauth.core.internal.httpkit import authenticated_user
from allauth.core.ratelimit import RateLimited
from allauth.decorators import rate_limit
from allauth.utils import get_form_class


class _BaseVerifyPhoneView(NextRedirectMixin, FormView):
    form_class = VerifyPhoneForm
    template_name = (
        f"account/confirm_phone_verification_code.{app_settings.TEMPLATE_EXTENSION}"
    )

    @cached_property
    def _action(self):
        action = self.request.POST.get("action")
        valid_actions = ["verify"]
        if self.process.can_change:
            valid_actions.append("change")
        if self.process.can_resend:
            valid_actions.append("resend")
        if action not in valid_actions:
            action = "verify"
        return action

    def get_form_class(self):
        if self._action == "change":
            return self._get_change_form_class()
        elif self._action == "resend":
            return Form
        return self._get_verify_form_class()

    def _get_change_form_class(self):
        return get_form_class(app_settings.FORMS, "change_phone", ChangePhoneForm)

    def _get_verify_form_class(self):
        return get_form_class(app_settings.FORMS, "verify_phone", self.form_class)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        if self._action == "change":
            kwargs["phone"] = self.process.phone
            kwargs["user"] = self.process.user
        elif self._action == "resend":
            pass
        else:
            kwargs["code"] = self.process.code
            kwargs["phone"] = self.process.phone
            kwargs["user"] = self.process.user
        return kwargs

    def form_valid(self, form) -> HttpResponse:
        if self._action == "change":
            return self._change_form_valid(form)
        elif self._action == "resend":
            return self._resend_form_valid(form)
        return self._verify_form_valid(form)

    def _resend_form_valid(self, form):
        try:
            self.process.resend()
        except RateLimited:
            adapter = get_adapter()
            adapter.add_message(
                self.request,
                messages.ERROR,
                message=adapter.error_messages["rate_limited"],
            )
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_verify_phone"))
        )

    def _change_form_valid(self, form):
        self.process.change_to(form.cleaned_data["phone"], form.account_already_exists)
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_verify_phone"))
        )

    def _verify_form_valid(self, form):
        self.process.finish()
        return self.respond_process_succeeded(form)

    def form_invalid(self, form) -> HttpResponse:
        if self._action == "change":
            return self._change_form_invalid(form)
        return self._verify_form_invalid(form)

    def _change_form_invalid(self, form):
        return super().form_invalid(form)

    def _verify_form_invalid(self, form):
        attempts_left = self.process.record_invalid_attempt()
        if attempts_left:
            return super().form_invalid(form)
        self.process.abort()
        return self.respond_process_failed(form)

    def get_context_data(self, **kwargs):
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        ret["can_change"] = self.process.can_change
        ret["can_resend"] = self.process.can_resend
        if self._action == "change":
            ret["change_form"] = ret["form"]
            ret["verify_form"] = self._get_verify_form_class()()
        else:
            ret["change_form"] = self._get_change_form_class()()
            ret["verify_form"] = ret["form"]
        ret.update(
            {
                "phone": self.process.phone,
                "action": self._action,
            }
        )
        return ret


@method_decorator(
    login_stage_required(
        stage=PhoneVerificationStage.key, redirect_urlname="account_login"
    ),
    name="dispatch",
)
class _VerifyPhoneSignupView(_BaseVerifyPhoneView):
    @method_decorator(never_cache)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        self.stage = request._login_stage  # type:ignore[attr-defined]
        self.process = flows.phone_verification.PhoneVerificationStageProcess.resume(
            self.stage
        )
        if not self.process:
            return self.stage.abort()
        return super().dispatch(request, *args, **kwargs)

    def respond_process_succeeded(self, form):
        return self.stage.exit()

    def respond_process_failed(self, form):
        adapter = get_adapter(self.request)
        adapter.add_message(
            self.request,
            messages.ERROR,
            message=adapter.error_messages["too_many_login_attempts"],
        )
        return self.stage.abort()


class _VerifyPhoneChangeView(_BaseVerifyPhoneView):
    @method_decorator(never_cache)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        self.process = flows.phone_verification.ChangePhoneVerificationProcess.resume(
            request
        )
        if not self.process:
            return HttpResponseRedirect(reverse("account_change_phone"))
        return super().dispatch(request, *args, **kwargs)

    def respond_process_succeeded(self, form):
        return HttpResponseRedirect(reverse("account_change_phone"))

    def respond_process_failed(self, form):
        return HttpResponseRedirect(reverse("account_change_phone"))

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update({"cancel_url": reverse("account_change_phone")})
        return ret


@method_decorator(login_not_required, name="dispatch")
def verify_phone(request: HttpRequest):
    if request.user.is_authenticated:
        return _VerifyPhoneChangeView.as_view()(request)
    return _VerifyPhoneSignupView.as_view()(request)


@method_decorator(login_required, name="dispatch")
@method_decorator(rate_limit(action="change_phone"), name="dispatch")
class ChangePhoneView(FormView):
    template_name = f"account/phone_change.{app_settings.TEMPLATE_EXTENSION}"
    form_class = ChangePhoneForm
    success_url = reverse_lazy("account_verify_phone")

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "change_phone", self.form_class)

    def get_form_kwargs(self) -> dict:
        ret = super().get_form_kwargs()
        self._phone_verified = get_adapter().get_phone(authenticated_user(self.request))
        if (
            self.request.POST.get("action") == "verify"
            and self._phone_verified
            and not self._phone_verified[1]
        ):
            # We're (re-)sending the verificaton code, so just feed the existing
            # phone to the form...
            ret["data"] = {"phone": self._phone_verified[0]}
            ret["phone"] = None
        else:
            ret["phone"] = self._phone_verified[0] if self._phone_verified else None
        ret["user"] = self.request.user
        return ret

    def form_valid(self, form) -> HttpResponse:
        flows.phone_verification.ChangePhoneVerificationProcess.initiate(
            self.request, form.cleaned_data["phone"]
        )
        return super().form_valid(form)

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        phone = None
        phone_verified = False
        if self._phone_verified:
            phone, phone_verified = self._phone_verified
        ret.update(
            {
                "phone": phone,
                "phone_verified": phone_verified,
            }
        )
        return ret


change_phone = ChangePhoneView.as_view()
