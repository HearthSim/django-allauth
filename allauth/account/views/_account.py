from __future__ import annotations

from django.utils.decorators import method_decorator
from django.views.generic.base import TemplateView

from allauth.account import app_settings
from allauth.account.internal.decorators import login_not_required
from allauth.account.internal.templatekit import get_entrance_context_data


@method_decorator(login_not_required, name="dispatch")
class AccountInactiveView(TemplateView):
    template_name = f"account/account_inactive.{app_settings.TEMPLATE_EXTENSION}"

    def get_context_data(self, **kwargs) -> dict:
        ret = super().get_context_data(**kwargs)
        ret.update(get_entrance_context_data(self.request))
        return ret


account_inactive = AccountInactiveView.as_view()
