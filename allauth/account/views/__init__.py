from allauth.account.views._account import AccountInactiveView, account_inactive
from allauth.account.views._email_change import EmailView, email
from allauth.account.views._email_verification import (
    ConfirmEmailVerificationCodeView,
    ConfirmEmailView,
    EmailVerificationSentView,
    confirm_email,
    email_verification_sent,
)
from allauth.account.views._login import (
    ConfirmLoginCodeView,
    LoginView,
    RequestLoginCodeView,
    confirm_login_code,
    login,
    request_login_code,
)
from allauth.account.views._logout import LogoutView, logout
from allauth.account.views._password_change import (
    PasswordChangeView,
    PasswordSetView,
    password_change,
    password_set,
)
from allauth.account.views._password_reset import (
    CompletePasswordResetView,
    ConfirmPasswordResetCodeView,
    PasswordResetDoneView,
    PasswordResetFromKeyDoneView,
    PasswordResetFromKeyView,
    PasswordResetView,
    complete_password_reset,
    confirm_password_reset_code,
    password_reset,
    password_reset_done,
    password_reset_from_key,
    password_reset_from_key_done,
)
from allauth.account.views._phone import ChangePhoneView, change_phone, verify_phone
from allauth.account.views._reauthenticate import (
    ConfirmReauthenticationCodeView,
    ReauthenticateView,
    RequestReauthenticationCodeView,
    confirm_reauthentication_code,
    reauthenticate,
    request_reauthentication_code,
)
from allauth.account.views._signup import (
    SignupByPasskeyView,
    SignupView,
    signup,
    signup_by_passkey,
)


__all__ = [
    "AccountInactiveView",
    "ChangePhoneView",
    "CompletePasswordResetView",
    "ConfirmEmailVerificationCodeView",
    "ConfirmEmailView",
    "ConfirmLoginCodeView",
    "ConfirmPasswordResetCodeView",
    "ConfirmReauthenticationCodeView",
    "EmailVerificationSentView",
    "EmailView",
    "LoginView",
    "LogoutView",
    "PasswordChangeView",
    "PasswordResetDoneView",
    "PasswordResetFromKeyDoneView",
    "PasswordResetFromKeyView",
    "PasswordResetView",
    "PasswordSetView",
    "ReauthenticateView",
    "RequestLoginCodeView",
    "RequestReauthenticationCodeView",
    "SignupByPasskeyView",
    "SignupView",
    "account_inactive",
    "change_phone",
    "complete_password_reset",
    "confirm_email",
    "confirm_login_code",
    "confirm_password_reset_code",
    "confirm_reauthentication_code",
    "email",
    "email_verification_sent",
    "login",
    "logout",
    "password_change",
    "password_reset",
    "password_reset_done",
    "password_reset_from_key",
    "password_reset_from_key_done",
    "password_set",
    "reauthenticate",
    "request_login_code",
    "request_reauthentication_code",
    "signup",
    "signup_by_passkey",
    "verify_phone",
]
