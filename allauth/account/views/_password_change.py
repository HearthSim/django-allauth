from __future__ import annotations

from typing import Any

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import ChangePasswordForm, SetPasswordForm
from allauth.account.internal import flows
from allauth.account.mixins import AjaxCapableProcessFormViewMixin, NextRedirectMixin
from allauth.account.views._decorators import sensitive_post_parameters_m
from allauth.decorators import rate_limit
from allauth.utils import get_form_class


@method_decorator(login_required, name="dispatch")
@method_decorator(rate_limit(action="change_password"), name="dispatch")
class PasswordChangeView(AjaxCapableProcessFormViewMixin, NextRedirectMixin, FormView):
    template_name = f"account/password_change.{app_settings.TEMPLATE_EXTENSION}"
    form_class = ChangePasswordForm

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "change_password", self.form_class)

    @sensitive_post_parameters_m
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any):
        # This view is @login_required
        user = self.request.user
        assert user.is_authenticated  # nosec
        if not user.has_usable_password():
            return HttpResponseRedirect(reverse("account_set_password"))
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get_default_success_url(self):
        return get_adapter().get_password_change_redirect_url(self.request)

    def form_valid(self, form) -> HttpResponse:
        form.save()
        flows.password_change.finalize_password_change(self.request, form.user)
        return super().form_valid(form)

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        # NOTE: For backwards compatibility
        ret["password_change_form"] = ret.get("form")
        # (end NOTE)
        return ret


password_change = PasswordChangeView.as_view()


@method_decorator(login_required, name="dispatch")
@method_decorator(
    # NOTE: 'change_password' (iso 'set_') is intentional, there is no need to
    # differentiate between set and change.
    rate_limit(action="change_password"),
    name="dispatch",
)
class PasswordSetView(AjaxCapableProcessFormViewMixin, NextRedirectMixin, FormView):
    template_name = f"account/password_set.{app_settings.TEMPLATE_EXTENSION}"
    form_class = SetPasswordForm

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "set_password", self.form_class)

    @sensitive_post_parameters_m
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any):
        user = self.request.user
        assert user.is_authenticated  # nosec
        if user.has_usable_password():
            return HttpResponseRedirect(reverse("account_change_password"))
        flows.reauthentication.raise_if_reauthentication_required(
            request, app="allauth.account"
        )
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get_default_success_url(self):
        return get_adapter().get_password_change_redirect_url(self.request)

    def form_valid(self, form) -> HttpResponse:
        form.save()
        flows.password_change.finalize_password_set(self.request, form.user)
        return super().form_valid(form)

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        # NOTE: For backwards compatibility
        ret["password_set_form"] = ret.get("form")
        # (end NOTE)
        return ret


password_set = PasswordSetView.as_view()
