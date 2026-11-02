from __future__ import annotations

from http import HTTPStatus
from typing import Any

from django.contrib import messages
from django.forms import Form
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import ChangeEmailForm, ConfirmEmailVerificationCodeForm
from allauth.account.internal import flows
from allauth.account.internal.decorators import login_not_required
from allauth.account.internal.templatekit import get_entrance_context_data
from allauth.account.mixins import (
    LogoutFunctionalityMixin,
    NextRedirectMixin,
    _ajax_response,
)
from allauth.account.models import EmailConfirmation, get_emailconfirmation_model
from allauth.account.stages import EmailVerificationStage, LoginStageController
from allauth.account.utils import user_display
from allauth.core.internal.httpkit import redirect
from allauth.core.ratelimit import RateLimited
from allauth.utils import get_form_class


@method_decorator(login_not_required, name="dispatch")
class ConfirmEmailView(NextRedirectMixin, LogoutFunctionalityMixin, TemplateView):
    template_name = f"account/email_confirm.{app_settings.TEMPLATE_EXTENSION}"

    def get(self, *args, **kwargs) -> HttpResponse:
        try:
            self.object = self.get_object()
            self.logout_other_user(self.object)
            if app_settings.CONFIRM_EMAIL_ON_GET:
                return self.post(*args, **kwargs)
        except Http404:
            self.object = None
        ctx = self.get_context_data()
        if not self.object and get_adapter().is_ajax(self.request):
            resp = HttpResponse()
            resp.status_code = HTTPStatus.BAD_REQUEST
        else:
            resp = self.render_to_response(ctx)
        return _ajax_response(self.request, resp, data=self.get_ajax_data())

    def logout_other_user(self, confirmation) -> None:
        """
        In the event someone clicks on an email confirmation link
        for one account while logged into another account,
        logout of the currently logged in account.
        """
        if (
            self.request.user.is_authenticated
            and self.request.user.pk != confirmation.email_address.user_id
        ):
            self.logout()

    def post(self, *args, **kwargs) -> HttpResponse:
        self.object = verification = self.get_object()
        email_address, response = flows.email_verification.verify_email_and_resume(
            self.request, verification
        )
        if response:
            return response
        if not email_address:
            return self.respond(False)

        self.logout_other_user(self.object)
        return self.respond(True)

    def respond(self, success):
        redirect_url = self.get_redirect_url()
        if not redirect_url:
            ctx = self.get_context_data()
            return self.render_to_response(ctx)
        return redirect(redirect_url)

    def get_object(self, queryset=None):
        key = self.kwargs["key"]
        model = get_emailconfirmation_model()
        emailconfirmation = model.from_key(key)
        if not emailconfirmation:
            raise Http404()
        return emailconfirmation

    def get_queryset(self):
        qs = EmailConfirmation.objects.all_valid()
        qs = qs.select_related("email_address__user")
        return qs

    def get_ajax_data(self) -> dict:
        ret: dict = {
            "can_confirm": bool(self.object),
        }
        if self.object:
            ret["email"] = self.object.email_address.email
            ret["user"] = {"display": user_display(self.object.email_address.user)}
        return ret

    def get_context_data(self, **kwargs) -> dict:
        ctx = super().get_context_data(**kwargs)
        ctx.update(get_entrance_context_data(self.request))
        ctx.update(
            {
                "confirmation": self.object,
                "can_confirm": self.object
                and self.object.email_address.can_set_verified(),
            }
        )
        if self.object:
            ctx["email"] = self.object.email_address.email
        return ctx

    def get_redirect_url(self) -> str:
        url = self.get_next_url()
        if not url:
            url = get_adapter(self.request).get_email_verification_redirect_url(
                self.object.email_address,
            )
        return url


confirm_email = ConfirmEmailView.as_view()


@method_decorator(login_not_required, name="dispatch")
class EmailVerificationSentView(TemplateView):
    template_name = f"account/verification_sent.{app_settings.TEMPLATE_EXTENSION}"

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        return ret


class ConfirmEmailVerificationCodeView(NextRedirectMixin, FormView):
    template_name = (
        f"account/confirm_email_verification_code.{app_settings.TEMPLATE_EXTENSION}"
    )
    form_class = ConfirmEmailVerificationCodeForm

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        self.stage = LoginStageController.enter(request, EmailVerificationStage.key)
        self._process = (
            flows.email_verification_by_code.EmailVerificationProcess.resume(request)
        )
        # preventing enumeration?
        verification_is_fake = self._process and "user_id" not in self._process.state
        # Can we at all continue?
        if (
            # No verification pending?
            (not self._process)  # Anonymous, yet no stage (or fake verifcation)?
            or (
                request.user.is_anonymous
                and not self.stage
                and not verification_is_fake
            )
        ):
            return HttpResponseRedirect(
                reverse(
                    "account_login" if request.user.is_anonymous else "account_email"
                )
            )
        return super().dispatch(request, *args, **kwargs)

    @cached_property
    def _action(self):
        action = self.request.POST.get("action")
        valid_actions = ["verify"]
        if self._process.can_change:
            valid_actions.append("change")
        if self._process.can_resend:
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
        return get_form_class(app_settings.FORMS, "change_email", ChangeEmailForm)

    def _get_verify_form_class(self):
        return get_form_class(
            app_settings.FORMS, "confirm_email_verification_code", self.form_class
        )

    def get_form_kwargs(self):
        ret = super().get_form_kwargs()
        if self._action == "change":
            pass
        elif self._action == "verify":
            ret["code"] = self._process.code if self._process else ""
            ret["user"] = self._process.user
            ret["email"] = self._process.email
        return ret

    def get_context_data(self, **kwargs):
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        ret["can_change"] = self._process.can_change
        ret["can_resend"] = self._process.can_resend
        ret["email"] = self._process.state["email"]
        ret["cancel_url"] = None if self.stage else reverse("account_email")
        if self._action == "change":
            ret["change_form"] = ret["form"]
            ret["verify_form"] = self._get_verify_form_class()()
        else:
            ret["change_form"] = self._get_change_form_class()()
            ret["verify_form"] = ret["form"]
        return ret

    def form_valid(self, form) -> HttpResponse:
        if self._action == "change":
            return self._change_form_valid(form)
        elif self._action == "resend":
            return self._resend_form_valid(form)
        return self._verify_form_valid(form)

    def _resend_form_valid(self, form):
        adapter = get_adapter()
        try:
            self._process.resend()
        except RateLimited:
            adapter.add_message(
                self.request,
                messages.ERROR,
                message=adapter.error_messages["rate_limited"],
            )
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_email_verification_sent"))
        )

    def _change_form_valid(self, form):
        self._process.change_to(form.cleaned_data["email"], form.account_already_exists)
        return HttpResponseRedirect(
            self.passthrough_next_url(reverse("account_email_verification_sent"))
        )

    def _verify_form_valid(self, form):
        email_address = self._process.finish()
        if self.stage:
            if not email_address:
                return self.stage.abort()
            return self.stage.exit()
        url = self.get_next_url()
        if url:
            pass
        elif not email_address:
            url = reverse("account_email")
        else:
            url = get_adapter(self.request).get_email_verification_redirect_url(
                email_address
            )
        return HttpResponseRedirect(url)

    def form_invalid(self, form):
        if self._action == "change":
            return self._change_form_invalid(form)
        return self._verify_form_invalid(form)

    def _verify_form_invalid(self, form):
        attempts_left = self._process.record_invalid_attempt()
        if attempts_left:
            return super().form_invalid(form)
        adapter = get_adapter(self.request)
        adapter.add_message(
            self.request,
            messages.ERROR,
            message=adapter.error_messages["too_many_login_attempts"],
        )
        return HttpResponseRedirect(reverse("account_login"))


@method_decorator(login_not_required, name="dispatch")
def email_verification_sent(request: HttpRequest) -> HttpResponseBase:
    if app_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED:
        return ConfirmEmailVerificationCodeView.as_view()(request)
    else:
        return EmailVerificationSentView.as_view()(request)
