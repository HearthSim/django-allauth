from __future__ import annotations

from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters


sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters("oldpassword", "password", "password1", "password2")
)
