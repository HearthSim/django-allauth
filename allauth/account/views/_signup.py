from __future__ import annotations

from typing import Any

from django.core.validators import validate_email
from django.forms import ValidationError
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.forms import SignupForm
from allauth.account.internal import flows
from allauth.account.internal.decorators import login_not_required
from allauth.account.internal.stagekit import clear_login
from allauth.account.internal.templatekit import get_entrance_context_data
from allauth.account.mixins import (
    AjaxCapableProcessFormViewMixin,
    CloseableSignupMixin,
    NextRedirectMixin,
    RedirectAuthenticatedUserMixin,
)
from allauth.account.stages import LoginStage
from allauth.account.views._decorators import sensitive_post_parameters_m
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.decorators import rate_limit
from allauth.utils import get_form_class


class SignupView(
    RedirectAuthenticatedUserMixin,
    CloseableSignupMixin,
    NextRedirectMixin,
    AjaxCapableProcessFormViewMixin,
    FormView,
):
    template_name = f"account/signup.{app_settings.TEMPLATE_EXTENSION}"
    form_class = SignupForm

    @method_decorator(rate_limit(action="signup"))
    @method_decorator(login_not_required)
    @sensitive_post_parameters_m
    @method_decorator(never_cache)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        return super().dispatch(request, *args, **kwargs)

    def _redirect_to_pending_stage(
        self, request: HttpRequest, stage: LoginStage
    ) -> HttpResponseRedirect | None:
        """
        In case you use login-by-code, and try and login using an unknown
        email address. Then, account enumeration kicks in. The code confirmation
        page shows up, and you'll get an email informing you no account exists,
        providing a link to the signup page. Yet, clicking that link redirects
        to the pending stage. Here, we are stopping that from happening, but
        only for true logins.
        """
        if not stage.login.signup:
            clear_login(request)
            return None
        return super()._redirect_to_pending_stage(request, stage)

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "signup", self.form_class)

    def form_valid(self, form) -> HttpResponse:
        self.user, resp = form.try_save(self.request)
        if resp:
            return resp
        try:
            redirect_url = self.get_success_url()
            return flows.signup.complete_signup(
                self.request,
                user=self.user,
                redirect_url=redirect_url,
                by_passkey=form.by_passkey,
            )
        except ImmediateHttpResponse as e:
            return e.response

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        form = ret["form"]
        email = self.request.session.get("account_verified_email")
        if email:
            email_keys = ["email"]
            if "email2" in app_settings.SIGNUP_FIELDS:
                email_keys.append("email2")
            for email_key in email_keys:
                form.fields[email_key].initial = email
        return ret

    def get_initial(self) -> dict:
        initial = super().get_initial()
        email = self.request.GET.get("email")
        if email:
            try:
                validate_email(email)
            except ValidationError:
                return initial
            initial["email"] = email
            if "email2" in app_settings.SIGNUP_FIELDS:
                initial["email2"] = email
        return initial


signup = SignupView.as_view()


class SignupByPasskeyView(SignupView):
    template_name = f"account/signup_by_passkey.{app_settings.TEMPLATE_EXTENSION}"

    def get_form_kwargs(self) -> dict:
        ret = super().get_form_kwargs()
        ret["by_passkey"] = True
        return ret


signup_by_passkey = SignupByPasskeyView.as_view()
