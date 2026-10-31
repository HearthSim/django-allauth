from __future__ import annotations

from django.http import HttpResponse
from django.utils.functional import cached_property
from django.views.generic.edit import FormView

from allauth.account.internal.flows._authenticate_by_code import (
    BaseConfirmAuthenticationCodeProcess,
)
from allauth.account.mixins import NextRedirectMixin


class BaseConfirmAuthenticationCodeView(NextRedirectMixin, FormView):
    _process: BaseConfirmAuthenticationCodeProcess

    @cached_property
    def _action(self) -> str:
        action = self.request.POST.get("action")
        valid_actions = ["verify"]
        if self._process.can_resend:
            valid_actions.append("resend")
        if action not in valid_actions:
            action = "verify"
        return action

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        if self._action != "resend":
            kwargs["code"] = self._process.code
        return kwargs

    def form_valid(self, form) -> HttpResponse:
        if self._action == "resend":
            return self._resend_form_valid(form)
        return self._verify_form_valid(form)

    def _resend_form_valid(self, form) -> HttpResponse:
        raise NotImplementedError

    def _verify_form_valid(self, form) -> HttpResponse:
        raise NotImplementedError
