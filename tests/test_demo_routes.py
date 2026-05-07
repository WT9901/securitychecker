from __future__ import annotations


def _csrf_token_from_session(client) -> str:
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_get_auth_pages(client):
    register_resp = client.get("/demo/register")
    login_resp = client.get("/demo/login")

    assert register_resp.status_code == 200
    assert login_resp.status_code == 200


def test_dashboard_redirects_when_not_logged_in(client):
    response = client.get("/demo/dashboard")

    assert response.status_code == 302
    assert "/demo/login" in response.location


def test_register_rejects_invalid_csrf(client):
    response = client.post(
        "/demo/register",
        data={
            "_csrf_token": "invalid-token",
            "fullName": "Alice Doe",
            "username": "alice_01",
            "email": "alice@example.com",
            "password": "StrongPass1!",
            "confirmPwd": "StrongPass1!",
            "agree": "on",
        },
    )

    assert response.status_code == 403
    payload = response.get_json()
    assert payload["error"].startswith("CSRF token invalid")


def test_register_then_login_flow(client):
    # Seed CSRF token
    client.get("/demo/register")
    csrf_register = _csrf_token_from_session(client)

    register_resp = client.post(
        "/demo/register",
        data={
            "_csrf_token": csrf_register,
            "fullName": "Alice Doe",
            "username": "alice_01",
            "email": "alice@example.com",
            "password": "StrongPass1!",
            "confirmPwd": "StrongPass1!",
            "agree": "on",
        },
    )
    assert register_resp.status_code == 302
    assert "/demo/login" in register_resp.location

    # Fetch login page and use current token
    client.get("/demo/login")
    csrf_login = _csrf_token_from_session(client)

    login_resp = client.post(
        "/demo/login",
        data={
            "_csrf_token": csrf_login,
            "email": "alice_01",
            "password": "StrongPass1!",
        },
    )
    assert login_resp.status_code == 302
    assert "/demo/dashboard" in login_resp.location

    dashboard_resp = client.get("/demo/dashboard")
    assert dashboard_resp.status_code == 200
