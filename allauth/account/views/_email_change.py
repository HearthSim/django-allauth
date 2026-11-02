from __future__ import annotations

from typing import Any

from django.contrib.auth.decorators import login_required
from django.core.validators import validate_email
from django.forms import ValidationError
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic.edit import FormView

from allauth.account import app_settings
from allauth.account.forms import AddEmailForm
from allauth.account.internal import flows
from allauth.account.internal.flows.email_verification import (
    send_verification_email_to_address,
)
from allauth.account.mixins import AjaxCapableProcessFormViewMixin, _ajax_response
from allauth.account.models import EmailAddress
from allauth.core.internal.httpkit import authenticated_user
from allauth.decorators import rate_limit
from allauth.utils import get_form_class


@method_decorator(login_required, name="dispatch")
@method_decorator(rate_limit(action="manage_email"), name="dispatch")
class EmailView(AjaxCapableProcessFormViewMixin, FormView):
    template_name = (
        f"account/email_change.{app_settings.TEMPLATE_EXTENSION}"
        if app_settings.CHANGE_EMAIL
        else f"account/email.{app_settings.TEMPLATE_EXTENSION}"
    )
    form_class = AddEmailForm
    success_url = reverse_lazy("account_email")

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, "add_email", self.form_class)

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        self._did_send_verification_email = False
        user = request.user
        assert user.is_authenticated  # nosec
        flows.manage_email.sync_user_email_address(user)
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict:
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form) -> HttpResponse:
        flows.manage_email.add_email(self.request, form)
        self._did_send_verification_email = True
        return super().form_valid(form)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        res = None
        if "action_add" in request.POST:
            res = super().post(request, *args, **kwargs)
        elif request.POST.get("email"):
            if "action_send" in request.POST:
                res = self._action_send(request)
            elif "action_remove" in request.POST:
                res = self._action_remove(request)
            elif "action_primary" in request.POST:
                res = self._action_primary(request)

            res = res or HttpResponseRedirect(self.get_success_url())
            # Given that we bypassed AjaxCapableProcessFormViewMixin,
            # we'll have to call invoke it manually...
            res = _ajax_response(request, res, data=self._get_ajax_data_if())
        else:
            # No email address selected
            res = HttpResponseRedirect(self.success_url)
            res = _ajax_response(request, res, data=self._get_ajax_data_if())
        return res

    def _get_email_address(self, request: HttpRequest):
        email = request.POST["email"]
        try:
            validate_email(email)
        except ValidationError:
            return None
        try:
            return EmailAddress.objects.get_for_user(
                user=authenticated_user(request), email=email
            )
        except EmailAddress.DoesNotExist:
            pass

    def _action_send(self, request: HttpRequest, *args: Any, **kwargs: Any):
        email_address = self._get_email_address(request)
        did_send_verification_email = False
        if email_address:
            did_send_verification_email = send_verification_email_to_address(
                self.request, email_address
            )
        self._did_send_verification_email = did_send_verification_email
        if (
            app_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED
            and did_send_verification_email
        ):
            return HttpResponseRedirect(reverse("account_email_verification_sent"))

    def _action_remove(self, request: HttpRequest, *args: Any, **kwargs: Any):
        email_address = self._get_email_address(request)
        if email_address:
            if flows.manage_email.delete_email(request, email_address):
                return HttpResponseRedirect(self.get_success_url())

    def _action_primary(self, request: HttpRequest, *args: Any, **kwargs: Any):
        email_address = self._get_email_address(request)
        if email_address:
            if flows.manage_email.mark_as_primary(request, email_address):
                return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        ret = super().get_context_data(**kwargs)
        emails = list(
            EmailAddress.objects.filter(user=self.request.user).order_by("email")
        )
        ret.update(
            {
                "emailaddresses": emails,
                "emailaddress_radios": [
                    {
                        "id": f"email_radio_{i}",
                        "checked": email.primary or len(emails) == 1,
                        "emailaddress": email,
                    }
                    for i, email in enumerate(emails)
                ],
                "add_email_form": ret.get("form"),
                "can_add_email": EmailAddress.objects.can_add_email(self.request.user),
            }
        )
        if app_settings.CHANGE_EMAIL:
            ret.update(
                {
                    "new_emailaddress": EmailAddress.objects.get_new(self.request.user),
                    "current_emailaddress": EmailAddress.objects.get_verified(
                        self.request.user
                    ),
                }
            )
        return ret

    def get_ajax_data(self):
        data = []
        for emailaddress in self.request.user.emailaddress_set.all().order_by("pk"):
            data.append(
                {
                    "id": emailaddress.pk,
                    "email": emailaddress.email,
                    "verified": emailaddress.verified,
                    "primary": emailaddress.primary,
                }
            )
        return data

    def get_success_url(self):
        if (
            self._did_send_verification_email
            and app_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED
        ):
            return reverse("account_email_verification_sent")
        return self.success_url


email = EmailView.as_view()
