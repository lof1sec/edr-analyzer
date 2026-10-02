"""Tests for authentication (setup / login / logout / me) and route protection."""

ADMIN_PASSWORD = "correct-horse-battery"


def test_status_needs_setup_when_no_users(client):
    assert client.get("/api/auth/status").json() == {
        "needs_setup": True,
        "authenticated": False,
        "username": None,
    }


def test_setup_creates_admin_and_logs_in(client):
    resp = client.post(
        "/api/auth/setup",
        json={"username": "admin", "password": ADMIN_PASSWORD},
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == "admin"

    assert client.get("/api/auth/status").json() == {
        "needs_setup": False,
        "authenticated": True,
        "username": "admin",
    }
    assert client.get("/api/auth/me").json()["username"] == "admin"


def test_setup_is_disabled_after_the_first_user(client):
    client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PASSWORD})

    again = client.post(
        "/api/auth/setup",
        json={"username": "second", "password": "another-long-password"},
    )
    assert again.status_code == 403


def test_setup_rejects_weak_credentials(client):
    short_password = client.post(
        "/api/auth/setup", json={"username": "admin", "password": "short"}
    )
    assert short_password.status_code == 422

    blank_username = client.post(
        "/api/auth/setup", json={"username": "  ", "password": ADMIN_PASSWORD}
    )
    assert blank_username.status_code == 422


def test_login_and_logout_flow(client):
    client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PASSWORD})
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").status_code == 401

    bad_login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "wrong-password"}
    )
    assert bad_login.status_code == 401

    good_login = client.post(
        "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    assert good_login.status_code == 200
    assert client.get("/api/auth/me").json()["username"] == "admin"

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_protected_routes_require_authentication(client):
    assert client.get("/api/datasets/").status_code == 401
    assert client.get("/api/graph/1").status_code == 401
    assert client.get("/api/graph/1/search", params={"q": "x"}).status_code == 401


def test_authenticated_user_reaches_protected_routes(admin_client):
    assert admin_client.get("/api/datasets/").status_code == 200


def test_change_password_requires_authentication(client):
    resp = client.post(
        "/api/auth/change-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "a-new-long-password"},
    )
    assert resp.status_code == 401


def test_change_password_happy_path(admin_client):
    new_password = "a-new-long-password"
    resp = admin_client.post(
        "/api/auth/change-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": new_password},
    )
    assert resp.status_code == 200

    # The current session stays valid.
    assert admin_client.get("/api/auth/me").status_code == 200

    admin_client.post("/api/auth/logout")
    assert (
        admin_client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        ).status_code
        == 401
    )
    assert (
        admin_client.post(
            "/api/auth/login", json={"username": "admin", "password": new_password}
        ).status_code
        == 200
    )


def test_change_password_rejects_wrong_current_password(admin_client):
    resp = admin_client.post(
        "/api/auth/change-password",
        json={
            "current_password": "definitely-wrong",
            "new_password": "a-new-long-password",
        },
    )
    assert resp.status_code == 400


def test_change_password_rejects_weak_new_password(admin_client):
    resp = admin_client.post(
        "/api/auth/change-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "short"},
    )
    assert resp.status_code == 422
