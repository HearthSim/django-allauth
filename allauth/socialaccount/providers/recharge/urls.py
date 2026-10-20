from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns

from .provider import RechargeProvider


urlpatterns = default_urlpatterns(RechargeProvider)
