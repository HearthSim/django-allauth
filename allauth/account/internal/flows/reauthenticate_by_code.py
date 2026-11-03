from __future__ import annotations

from django.http import HttpRequest

from allauth.account import app_settings, signals
from allauth.account.internal.flows._authenticate_by_code import (
    BaseConfirmAuthenticationCodeProcess,
)
from allauth.account.internal.flows.email_verification import verify_email_indirectly
from allauth.account.internal.flows.login import record_authentication
from allauth.account.internal.flows.phone_verification import verify_phone_indirectly
from allauth.account.internal.flows.reauthentication import (
    raise_if_reauthentication_method_not_enabled,
)


REAUTHENTICATION_CODE_SESSION_KEY = "account_email_reauthentication_code"


class ConfirmReauthenticationCodeProcess(BaseConfirmAuthenticationCodeProcess):
    def __init__(self, request: HttpRequest, state: dict, user) -> None:
        self.request = request
        super().__init__(
            state=state,
            timeout=app_settings.LOGIN_BY_CODE_TIMEOUT,
            max_attempts=app_settings.LOGIN_BY_CODE_MAX_ATTEMPTS,
            user=user,
        )

    def finish(self) -> None:
        raise_if_reauthentication_method_not_enabled("code")
        email = self.state.get("email")
        phone = self.state.get("phone")
        user = self.user
        assert user  # nosec
        record_authentication(
            self.request,
            user,
            method="code",
            email=email,
            phone=phone,
            reauthenticated=True,
        )
        if email:
            verify_email_indirectly(self.request, user, email)
        if phone:
            verify_phone_indirectly(self.request, user, phone)
        self.request.session.pop(REAUTHENTICATION_CODE_SESSION_KEY, None)

    def record_invalid_attempt(self) -> bool:
        has_attempts_left = super().record_invalid_attempt()
        if self.user:
            signals.login_code_rejected.send(
                sender=ConfirmReauthenticationCodeProcess,
                request=self.request,
                user=self.user,
                last_attempt=not has_attempts_left,
            )
        return has_attempts_left

    def abort(self) -> None:
        self.request.session.pop(REAUTHENTICATION_CODE_SESSION_KEY, None)

    def persist(self) -> None:
        self.request.session[REAUTHENTICATION_CODE_SESSION_KEY] = self.state

    @classmethod
    def initiate(
        cls,
        *,
        request: HttpRequest,
        user,
        email: str | None = None,
        phone: str | None = None,
    ) -> ConfirmReauthenticationCodeProcess:
        raise_if_reauthentication_method_not_enabled("code")
        state = cls.initial_state(user=user, email=email, phone=phone)
        process = ConfirmReauthenticationCodeProcess(
            request=request, user=user, state=state
        )
        process.send()
        process.persist()
        return process

    @classmethod
    def resume(cls, request: HttpRequest) -> ConfirmReauthenticationCodeProcess | None:
        if "code" not in app_settings.REAUTHENTICATION_METHODS:
            return None
        state = request.session.get(REAUTHENTICATION_CODE_SESSION_KEY)
        if not state or not request.user.is_authenticated:
            return None
        process = ConfirmReauthenticationCodeProcess(
            request=request, user=request.user, state=state
        )
        return process.abort_if_invalid()
