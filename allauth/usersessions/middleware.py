from django.http import HttpRequest

from allauth.usersessions.internal import usersessionkit


class UserSessionsMiddleware:
    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        usersessionkit.track_activity(
            request,
            user=getattr(request, "user", None),
            session=getattr(request, "session", None),
        )
        response = self.get_response(request)
        return response
