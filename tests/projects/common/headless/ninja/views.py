from ninja import NinjaAPI

from allauth.headless.contrib.ninja.security import jwt_token_auth, x_session_token_auth


api = NinjaAPI(urls_namespace="headless_ninja")


@api.get("/session-resource", auth=[x_session_token_auth], url_name="session_resource")
@api.get("/jwt-resource", auth=[jwt_token_auth], url_name="jwt_resource")
def resource(request):
    data = {"resource": "ok"}
    if "userinfo" in request.GET:
        user = (
            request.auth if hasattr(request.auth, "is_authenticated") else request.user
        )
        data["user_email"] = user.email
    return data
