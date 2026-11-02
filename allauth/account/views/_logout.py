from __future__ import annotations

from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.generic.base import TemplateView

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.internal.decorators import login_not_required
from allauth.account.mixins import (
    LogoutFunctionalityMixin,
    NextRedirectMixin,
    _ajax_response,
)
from allauth.core.internal.httpkit import redirect


@method_decorator(login_not_required, name="dispatch")
class LogoutView(NextRedirectMixin, LogoutFunctionalityMixin, TemplateView):
    template_name = f"account/logout.{app_settings.TEMPLATE_EXTENSION}"

    def get(self, *args, **kwargs) -> HttpResponse:
        response: HttpResponse
        if app_settings.LOGOUT_ON_GET:
            return self.post(*args, **kwargs)
        if not self.request.user.is_authenticated:
            response = redirect(self.get_redirect_url())
            return _ajax_response(self.request, response)
        ctx = self.get_context_data()
        response = self.render_to_response(ctx)
        return _ajax_response(self.request, response)

    def post(self, *args, **kwargs) -> HttpResponse:
        url = self.get_redirect_url()
        self.logout()
        response = redirect(url)
        return _ajax_response(self.request, response)

    def get_redirect_url(self) -> str:
        return self.get_next_url() or get_adapter(self.request).get_logout_redirect_url(
            self.request
        )


logout = LogoutView.as_view()
