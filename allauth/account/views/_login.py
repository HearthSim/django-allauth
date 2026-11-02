from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied
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

from allauth import app_settings as allauth_app_settings
from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import ConfirmLoginCodeForm, LoginForm, RequestLoginCodeForm
from allauth.account.internal import flows
from allauth.account.internal.decorators import login_not_required, login_stage_required
from allauth.account.internal.templatekit import get_entrance_context_data
from allauth.account.mixins import (
    AjaxCapableProcessFormViewMixin,
    NextRedirectMixin,
    RedirectAuthenticatedUserMixin,
)
from allauth.account.stages import LoginByCodeStage
from allauth.account.views._decorators import sensitive_post_parameters_m
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.core.ratelimit import RateLimited
from allauth.decorators import rate_limit
from allauth.utils import get_form_class


class LoginView(
    NextRedirectMixin,
    RedirectAuthenticatedUserMixin,
    AjaxCapableProcessFormViewMixin,
    FormView,
):
    form_class = LoginForm
    template_name = f"account/login.{app_settings.TEMPLATE_EXTENSION}"
    success_url = None

    @method_decorator(rate_limit(action="login"))
    @method_decorator(login_not_required)
    @sensitive_post_parameters_m
    @method_decorator(never_cache)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        if allauth_app_settings.SOCIALACCOUNT_ONLY and request.method != "GET":
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "login", self.form_class)

    def form_valid(self, form) -> HttpResponse:
        redirect_url = self.get_success_url()
        try:
            return form.login(self.request, redirect_url=redirect_url)
        except ImmediateHttpResponse as e:
            return e.response

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        return ret


login = LoginView.as_view()


class RequestLoginCodeView(RedirectAuthenticatedUserMixin, NextRedirectMixin, FormView):
    form_class = RequestLoginCodeForm
    template_name = f"account/request_login_code.{app_settings.TEMPLATE_EXTENSION}"

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "request_login_code", self.form_class)

    def form_valid(self, form) -> HttpResponse:
        flows.login_by_code.LoginCodeVerificationProcess.initiate(
            request=self.request,
            user=form._user,
            email=form.cleaned_data.get("email"),
            phone=form.cleaned_data.get("phone"),
        )
        return super().form_valid(form)

    def get_success_url(self):
        if self.request.user.is_authenticated:
            return None
        url = reverse_lazy("account_confirm_login_code")
        url = self.passthrough_next_url(reverse("account_confirm_login_code"))
        return url

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        return ret


request_login_code = RequestLoginCodeView.as_view()


def _login_by_code_urlname() -> str:
    # NOTE: Having this as a method instead of a constant allows changing
    # settings in test cases...
    return (
        "account_request_login_code"
        if app_settings.LOGIN_BY_CODE_ENABLED
        else "account_login"
    )


@method_decorator(
    login_stage_required(
        stage=LoginByCodeStage.key, redirect_urlname=(_login_by_code_urlname())
    ),
    name="dispatch",
)
class ConfirmLoginCodeView(NextRedirectMixin, FormView):
    form_class = ConfirmLoginCodeForm
    template_name = f"account/confirm_login_code.{app_settings.TEMPLATE_EXTENSION}"

    @method_decorator(never_cache)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        self.stage = request._login_stage  # type:ignore[attr-defined]
        self._process = flows.login_by_code.LoginCodeVerificationProcess.resume(
            self.stage
        )
        if not self._process:
            return HttpResponseRedirect(reverse(_login_by_code_urlname()))
        return super().dispatch(request, *args, **kwargs)

    @cached_property
    def _action(self) -> str:
        action = self.request.POST.get("action")
        valid_actions = ["verify"]
        if self._process.can_resend:
            valid_actions.append("resend")
        if action not in valid_actions:
            action = "verify"
        return action

    def get_form_class(self):
        if self._action == "resend":
            return Form
        return get_form_class(app_settings.FORMS, "confirm_login_code", self.form_class)

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        if self._action == "resend":
            pass
        else:
            kwargs["code"] = self._process.code
        return kwargs

    def form_valid(self, form) -> HttpResponse:
        if self._action == "resend":
            return self._resend_form_valid(form)
        return self._verify_form_valid(form)

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
            self.passthrough_next_url(reverse("account_confirm_login_code"))
        )

    def _verify_form_valid(self, form) -> HttpResponse:
        redirect_url = self.get_next_url()
        return self._process.finish(redirect_url)

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
            reverse(
                _login_by_code_urlname()
                if self._process.state["initiated_by_user"]
                else "account_login"
            )
        )

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        email = self._process.state.get("email")
        phone = self._process.state.get("phone")
        ret.update(
            {
                "can_resend": self._process.can_resend,
                "email": email,
                "phone": phone,
                "verify_form": ret["form"],
            }
        )
        return ret


confirm_login_code = ConfirmLoginCodeView.as_view()
