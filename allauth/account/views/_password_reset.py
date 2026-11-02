from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import (
    ConfirmPasswordResetCodeForm,
    ResetPasswordForm,
    ResetPasswordKeyForm,
    UserTokenForm,
)
from allauth.account.internal import flows
from allauth.account.internal.decorators import login_not_required
from allauth.account.internal.templatekit import get_entrance_context_data
from allauth.account.mixins import (
    AjaxCapableProcessFormViewMixin,
    LogoutFunctionalityMixin,
    NextRedirectMixin,
    _ajax_response,
)
from allauth.core import ratelimit
from allauth.core.internal.httpkit import redirect
from allauth.decorators import rate_limit
from allauth.utils import get_form_class


INTERNAL_RESET_SESSION_KEY = "_password_reset_key"


@method_decorator(login_not_required, name="dispatch")
class PasswordResetView(NextRedirectMixin, AjaxCapableProcessFormViewMixin, FormView):
    template_name = f"account/password_reset.{app_settings.TEMPLATE_EXTENSION}"
    form_class = ResetPasswordForm
    success_url = reverse_lazy("account_reset_password_done")

    def get_success_url(self) -> str:
        if not app_settings.PASSWORD_RESET_BY_CODE_ENABLED:
            return super().get_success_url()
        return self.passthrough_next_url(reverse("account_confirm_password_reset_code"))

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "reset_password", self.form_class)

    def form_valid(self, form) -> HttpResponse:
        r429 = ratelimit.consume_or_429(
            self.request,
            action="reset_password",
            key=form.cleaned_data["email"].lower(),
        )
        if r429:
            return r429
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        # NOTE: For backwards compatibility
        ret["password_reset_form"] = ret.get("form")
        # (end NOTE)
        return ret


password_reset = PasswordResetView.as_view()


@method_decorator(login_not_required, name="dispatch")
class PasswordResetDoneView(TemplateView):
    template_name = f"account/password_reset_done.{app_settings.TEMPLATE_EXTENSION}"

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        return ret


password_reset_done = PasswordResetDoneView.as_view()


@method_decorator(rate_limit(action="reset_password_from_key"), name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class PasswordResetFromKeyView(
    AjaxCapableProcessFormViewMixin,
    NextRedirectMixin,
    LogoutFunctionalityMixin,
    FormView,
):
    template_name = f"account/password_reset_from_key.{app_settings.TEMPLATE_EXTENSION}"
    form_class = ResetPasswordKeyForm
    success_url = reverse_lazy("account_reset_password_from_key_done")
    reset_url_key = "set-password"

    def get_form_class(self):
        return get_form_class(
            app_settings.FORMS, "reset_password_from_key", self.form_class
        )

    def dispatch(self, request: HttpRequest, uidb36, key, **kwargs) -> HttpResponseBase:
        self.request = request
        self.key = key

        user_token_form_class = get_form_class(
            app_settings.FORMS, "user_token", UserTokenForm
        )
        is_ajax = get_adapter().is_ajax(request)
        if self.key == self.reset_url_key or is_ajax:
            if not is_ajax:
                self.key = self.request.session.get(INTERNAL_RESET_SESSION_KEY, "")
            # (Ab)using forms here to be able to handle errors in XHR #890
            token_form = user_token_form_class(data={"uidb36": uidb36, "key": self.key})
            if token_form.is_valid():
                self.reset_user = token_form.reset_user

                # In the event someone clicks on a password reset link
                # for one account while logged into another account,
                # logout of the currently logged in account.
                if (
                    self.request.user.is_authenticated
                    and self.request.user.pk != self.reset_user.pk
                ):
                    self.logout()
                    self.request.session[INTERNAL_RESET_SESSION_KEY] = self.key

                return super().dispatch(request, uidb36, self.key, **kwargs)
        else:
            token_form = user_token_form_class(data={"uidb36": uidb36, "key": self.key})
            if token_form.is_valid():
                # Store the key in the session and redirect to the
                # password reset form at a URL without the key. That
                # avoids the possibility of leaking the key in the
                # HTTP Referer header.
                self.request.session[INTERNAL_RESET_SESSION_KEY] = self.key
                redirect_url = self.passthrough_next_url(
                    self.request.path.replace(self.key, self.reset_url_key)
                )
                return redirect(redirect_url)

        self.reset_user = None
        response = self.render_to_response(self.get_context_data(token_fail=True))
        return _ajax_response(self.request, response, form=token_form)

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        ret["action_url"] = reverse(
            "account_reset_password_from_key",
            kwargs={
                "uidb36": self.kwargs["uidb36"],
                "key": self.kwargs["key"],
            },
        )
        return ret

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.reset_user
        kwargs["temp_key"] = self.key
        return kwargs

    def form_valid(self, form) -> HttpResponse:
        form.save()
        resp = flows.password_reset.finalize_password_reset(
            self.request, self.reset_user
        )
        if resp:
            return resp
        return super().form_valid(form)


password_reset_from_key = PasswordResetFromKeyView.as_view()


@method_decorator(login_not_required, name="dispatch")
class PasswordResetFromKeyDoneView(TemplateView):
    template_name = (
        f"account/password_reset_from_key_done.{app_settings.TEMPLATE_EXTENSION}"
    )

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        return ret


password_reset_from_key_done = PasswordResetFromKeyDoneView.as_view()


@method_decorator(rate_limit(action="reset_password_from_key"), name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class CompletePasswordResetView(
    NextRedirectMixin,
    FormView,
):
    template_name = f"account/password_reset_from_key.{app_settings.TEMPLATE_EXTENSION}"
    form_class = ResetPasswordKeyForm
    success_url = reverse_lazy("account_password_reset_completed")

    def dispatch(self, request: HttpRequest, **kwargs) -> HttpResponseBase:
        self._process = (
            flows.password_reset_by_code.PasswordResetVerificationProcess.resume(
                request
            )
        )
        if not self._process:
            return HttpResponseRedirect(
                self.passthrough_next_url(reverse("account_reset_password"))
            )
        if not self._process.state.get("code_confirmed"):
            return HttpResponseRedirect(reverse("account_confirm_password_reset_code"))
        return super().dispatch(request, **kwargs)

    def get_form_class(self):
        return get_form_class(
            app_settings.FORMS, "reset_password_from_key", self.form_class
        )

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        ret["action_url"] = reverse("account_complete_password_reset")
        return ret

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self._process.user
        return kwargs

    def form_valid(self, form):
        form.save()
        resp = self._process.finish()
        if resp:
            return resp
        return super().form_valid(form)


complete_password_reset = CompletePasswordResetView.as_view()


class ConfirmPasswordResetCodeView(NextRedirectMixin, FormView):
    template_name = (
        f"account/confirm_password_reset_code.{app_settings.TEMPLATE_EXTENSION}"
    )
    form_class = ConfirmPasswordResetCodeForm

    @method_decorator(login_not_required)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        self._process = (
            flows.password_reset_by_code.PasswordResetVerificationProcess.resume(
                request
            )
        )
        if not self._process:
            return HttpResponseRedirect(reverse("account_login"))
        if self._process.state.get("code_confirmed"):
            return HttpResponseRedirect(reverse("account_complete_password_reset"))
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return get_form_class(
            app_settings.FORMS, "confirm_password_reset_code", self.form_class
        )

    def get_form_kwargs(self):
        ret = super().get_form_kwargs()
        ret["code"] = self._process.code
        return ret

    def get_context_data(self, **kwargs):
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        ret["email"] = self._process.state["email"]
        ret["verify_form"] = ret["form"]
        return ret

    def form_valid(self, form):
        self._process.confirm_code()
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_complete_password_reset"))
        )

    def form_invalid(self, form):
        attempts_left = self._process.record_invalid_attempt()
        if attempts_left:
            return super().form_invalid(form)
        adapter = get_adapter(self.request)
        adapter.add_message(
            self.request,
            messages.ERROR,
            message=adapter.error_messages["too_many_login_attempts"],
        )
        return HttpResponseRedirect(self.passthrough_next_url(reverse("account_login")))


confirm_password_reset_code = ConfirmPasswordResetCodeView.as_view()
