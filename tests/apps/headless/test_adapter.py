from http import HTTPStatus

from allauth.headless.adapter import DefaultHeadlessAdapter


class ResponseMetaHeadlessAdapter(DefaultHeadlessAdapter):
    def populate_response_meta(self, request, meta):
        meta["custom"] = "value"


def test_populate_response_meta(settings, client, headless_reverse):
    settings.HEADLESS_ADAPTER = (
        "tests.apps.headless.test_adapter.ResponseMetaHeadlessAdapter"
    )
    response = client.post(
        headless_reverse("headless:account:resend_login_code"),
    )
    assert response.status_code == HTTPStatus.CONFLICT
    data = response.json()
    assert "data" not in data
    assert data["meta"]["custom"] == "value"
