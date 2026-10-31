from __future__ import annotations

from django.http import HttpRequest

from allauth.account import app_settings, signals
from allauth.account.internal.flows._authenticate_by_code import (
    BaseConfirmAuthenticationCodeProcess,
)
from allauth.account.internal.flows.email_verification import verify_email_indirectly
from allauth.account.internal.flows.login import perform_login, record_authentication
from allauth.account.internal.flows.phone_verification import verify_phone_indirectly
from allauth.account.internal.stagekit import clear_login, stash_login
from allauth.account.models import Login
from allauth.account.stages import LoginByCodeStage, LoginStageController


LOGIN_CODE_STATE_KEY = "login_code"


class LoginCodeVerificationProcess(BaseConfirmAuthenticationCodeProcess):
    def __init__(self, stage) -> None:
        self.stage = stage
        self.request = stage.request
        super().__init__(
            state=stage.state,
            timeout=app_settings.LOGIN_BY_CODE_TIMEOUT,
            max_attempts=app_settings.LOGIN_BY_CODE_MAX_ATTEMPTS,
            user=stage.login.user,
        )

    def finish(self, redirect_url: str | None):
        email = self.state.get("email")
        phone = self.state.get("phone")
        user = self.user
        assert user  # nosec
        record_authentication(
            self.request, user, method="code", email=email, phone=phone
        )
        if email:
            verify_email_indirectly(self.request, user, email)
        if phone:
            verify_phone_indirectly(self.request, user, phone)
        if self.state["initiated_by_user"]:
            # Just requesting a login code does is not considered to be a real login,
            # yet, is needed in order to make the stage machinery work. Now that we've
            # completed the code, let's start a real login.
            login = Login(
                user=user,
                redirect_url=redirect_url,
                email=email,
            )
            return perform_login(self.request, login)
        else:
            return self.stage.exit()

    def record_invalid_attempt(self) -> bool:
        has_attempts_left = super().record_invalid_attempt()
        if self.user:
            signals.login_code_rejected.send(
                sender=LoginCodeVerificationProcess,
                request=self.request,
                user=self.user,
                last_attempt=not has_attempts_left,
            )
        return has_attempts_left

    def abort(self) -> None:
        clear_login(self.request)

    def persist(self) -> None:
        stash_login(self.request, self.stage.login)

    @classmethod
    def initiate(
        cls,
        *,
        request: HttpRequest,
        user,
        email: str | None = None,
        phone: str | None = None,
        stage=None,
    ) -> LoginCodeVerificationProcess:
        initial_state = cls.initial_state(user=user, email=email, phone=phone)
        initial_state["initiated_by_user"] = stage is None
        if not stage:
            login = Login(user=user, email=email)
            login.state["stages"] = {"current": "login_by_code"}
            stage = LoginByCodeStage(
                LoginStageController(request, login), request, login
            )
        stage.state.update(initial_state)
        process = LoginCodeVerificationProcess(stage=stage)
        process.send()
        process.persist()
        return process

    @classmethod
    def resume(cls, stage):
        process = LoginCodeVerificationProcess(stage=stage)
        return process.abort_if_invalid()
