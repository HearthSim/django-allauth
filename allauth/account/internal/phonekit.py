from django.contrib.auth.base_user import AbstractBaseUser

from allauth.account.adapter import get_adapter


def get_verified_phone(user: AbstractBaseUser) -> str | None:
    try:
        phone_data = get_adapter().get_phone(user)
    except NotImplementedError:
        return None
    if phone_data:
        phone, verified = phone_data
        if verified:
            return phone
    return None
