"""Tests for provisioning the admin from the environment (``app/bootstrap.py``)."""
from app.bootstrap import ensure_admin_user, get_admin_credentials
from app.models import User
from app.security import hash_password, verify_password


def test_get_admin_credentials_defaults_to_postgres(monkeypatch):
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("POSTGRES_USER", "dbadmin")
    monkeypatch.setenv("POSTGRES_PASSWORD", "db-secret-password")

    assert get_admin_credentials() == ("dbadmin", "db-secret-password")


def test_get_admin_credentials_prefers_admin_override(monkeypatch):
    monkeypatch.setenv("POSTGRES_USER", "dbadmin")
    monkeypatch.setenv("POSTGRES_PASSWORD", "db-secret-password")
    monkeypatch.setenv("ADMIN_USERNAME", "webadmin")
    monkeypatch.setenv("ADMIN_PASSWORD", "web-secret-password")

    assert get_admin_credentials() == ("webadmin", "web-secret-password")


def test_get_admin_credentials_none_without_env(monkeypatch):
    for var in ("ADMIN_USERNAME", "ADMIN_PASSWORD", "POSTGRES_USER", "POSTGRES_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    assert get_admin_credentials() is None


def test_admin_can_log_in_with_postgres_credentials(client, db_session, monkeypatch):
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("POSTGRES_USER", "dbadmin")
    monkeypatch.setenv("POSTGRES_PASSWORD", "db-secret-password")

    ensure_admin_user(db_session)

    assert db_session.query(User).filter_by(username="dbadmin").count() == 1
    resp = client.post(
        "/api/auth/login",
        json={"username": "dbadmin", "password": "db-secret-password"},
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == "dbadmin"


def test_ensure_admin_user_is_idempotent_and_keeps_changed_password(db_session, monkeypatch):
    monkeypatch.setenv("POSTGRES_USER", "dbadmin")
    monkeypatch.setenv("POSTGRES_PASSWORD", "db-secret-password")
    ensure_admin_user(db_session)

    user = db_session.query(User).filter_by(username="dbadmin").one()
    user.password_hash = hash_password("changed-in-app-password")
    db_session.commit()

    ensure_admin_user(db_session)  # what the next restart would do

    db_session.refresh(user)
    assert verify_password("changed-in-app-password", user.password_hash)
    assert db_session.query(User).count() == 1


def test_ensure_admin_user_noop_without_credentials(db_session, monkeypatch):
    for var in ("ADMIN_USERNAME", "ADMIN_PASSWORD", "POSTGRES_USER", "POSTGRES_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    assert ensure_admin_user(db_session) is None
    assert db_session.query(User).count() == 0
