Session Tokens
==============

Introduction
------------

When using allauth headless in non-browser contexts, such as mobile apps, a
session token is used to keep track of the authentication state. This session
token is handed over by the app by providing the ``X-Session-Token`` request
header. The token is only accepted while the Django session still authenticates
the user using Django's standard session auth hash check. Logging out or changing
the password therefore invalidates it immediately.

If you do not have any requirements that prescribe a specific token strategy,
the simplest way forward is to use the ``X-Session-Token`` authentication
mechanism for your own APIs as well.  In order to do so, integration with Django
Ninja and Django REST framework is offered out of the box.


Securing Your API Endpoints
---------------------------

Django Ninja
~~~~~~~~~~~~

For Django Ninja, the following security class is available:

.. autoclass:: allauth.headless.contrib.ninja.security.XSessionTokenAuth
   :members:

An example on how to use that security class in your own code is listed below:

.. code-block:: python

    from allauth.headless.contrib.ninja.security import x_session_token_auth
    from ninja import NinjaAPI

    api = NinjaAPI()

    @api.get("/your/own/api", auth=[x_session_token_auth])
    def your_own_api(request):
        ...

By default, missing or invalid session tokens and sessions that do not
authenticate a user are rejected. To make authentication optional, subclass
the security class and enable anonymous users:

.. code-block:: python

    from allauth.headless.contrib.ninja.security import XSessionTokenAuth

    class OptionalXSessionTokenAuth(XSessionTokenAuth):
        allow_anonymous_users = True

Missing tokens and valid sessions without an authenticated user then produce
an ``AnonymousUser``. Invalid session tokens remain rejected. To allow those as
well, set ``allow_invalid_session_tokens = True``. In both cases,
``request.user`` is set to the returned ``AnonymousUser``.


Django REST framework
~~~~~~~~~~~~~~~~~~~~~

For Django REST framework, the following authentication class is available:

.. autoclass:: allauth.headless.contrib.rest_framework.authentication.XSessionTokenAuthentication
   :members:

An example on how to use that authentication class in your own code is listed below:

.. code-block:: python

    from allauth.headless.contrib.rest_framework.authentication import (
        XSessionTokenAuthentication,
    )
    from rest_framework import permissions
    from rest_framework.views import APIView

    class YourOwnAPIView(APIView):

        authentication_classes = [
            XSessionTokenAuthentication,
        ]
        permission_classes = [permissions.IsAuthenticated]

        def get(self, request):
            ...

By default, invalid session tokens and sessions that do not authenticate an
active user are ignored. This matches Django REST framework's session
authentication behavior. To reject either case, subclass the authentication
class and set the corresponding option to ``False``:

.. code-block:: python

    class StrictXSessionTokenAuthentication(XSessionTokenAuthentication):
        allow_anonymous_user = False
        allow_invalid_session_tokens = False

When disabled, the corresponding condition raises DRF's
``AuthenticationFailed`` exception. If this authentication class is listed
first on the view, DRF responds with status ``401`` and an
``X-Session-Token`` authentication challenge.
