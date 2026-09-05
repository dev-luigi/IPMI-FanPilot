"""Phase 10 — SEC-03/04/05/07 regression tests.

Each test maps to a finding from the adversarial security audit and, where the
audit supplied a reproduction, asserts the *attack* fails rather than merely
asserting the happy path still works.

- SEC-03/F7  password change must revoke existing sessions (credential fingerprint,
              fail-closed when the claim is absent)
- SEC-04/F5  anonymous pre-setup auth-disable, and /setup leaving auth off
- SEC-05/F6  stale-but-signed cookie rewriting the account via /configure
- SEC-07/F11 GET /system/app-config/{key} handing out session_secret

NOTE on fixtures: `client` / `client_auth` are SYNC fixtures driving their own
event loop, so route-level tests here are sync and go through HTTP only — mixing
them with `await bm.auth...` would run on a different loop. Manager-level tests
use the async `auth_manager` fixture instead. asyncio_mode="auto" is project-wide.
"""

from __future__ import annotations

import pytest


# ============================================================ SEC-03 / F7


async def test_password_change_invalidates_token_fingerprint(auth_manager):
    """The whole point of F7: changing the password must revoke issued sessions."""
    am, _db = auth_manager
    await am.create_user("alice", "old-password")

    token = await am.create_session_token_for("alice")
    cfp_before = await am.credential_fingerprint("alice")
    assert am.token_matches_fingerprint(token, cfp_before)

    await am.update_password("alice", "new-password")

    cfp_after = await am.credential_fingerprint("alice")
    assert cfp_after != cfp_before
    assert am.token_matches_fingerprint(token, cfp_after) is False


async def test_username_change_also_invalidates(auth_manager):
    """The fingerprint covers the username too, so a rename revokes as well."""
    am, _db = auth_manager
    await am.create_user("alice", "pw")
    token = await am.create_session_token_for("alice")

    await am.replace_user("bob", "pw")

    cfp_bob = await am.credential_fingerprint("bob")
    assert cfp_bob is not None
    assert am.token_matches_fingerprint(token, cfp_bob) is False


async def test_legacy_token_without_cfp_is_rejected(auth_manager):
    """Fail-closed: a pre-upgrade token carries no `cfp` and must NOT be honoured.

    This is the decision that logs everyone out once on upgrade. A forged token
    would omit the claim just as a legacy one does, so "absent" cannot mean "ok".
    """
    am, _db = auth_manager
    await am.create_user("alice", "pw")

    legacy = am.create_session_token("alice")  # no cfp, the pre-2.1 shape
    assert am.verify_session_token(legacy) == "alice"  # signature still valid

    cfp = await am.credential_fingerprint("alice")
    assert am.token_matches_fingerprint(legacy, cfp) is False


async def test_fingerprint_is_none_for_unknown_user(auth_manager):
    am, _db = auth_manager
    assert await am.credential_fingerprint("nobody") is None


async def test_fingerprint_does_not_leak_the_hash(auth_manager):
    """Only an HMAC of the bcrypt hash travels in the cookie, never the hash."""
    am, db = auth_manager
    await am.create_user("alice", "pw")
    row = await db.fetchone(
        "SELECT password_hash FROM users WHERE username = ?", ("alice",)
    )

    cfp = await am.credential_fingerprint("alice")
    assert row["password_hash"] not in cfp
    assert len(cfp) == 32


async def test_malformed_token_fails_closed(auth_manager):
    """Garbage in the cookie must return False, never raise."""
    am, _db = auth_manager
    for junk in ["", "not-a-token", "a.b.c", "!!!.###", "eyJhIjoxfQ"]:
        assert am.token_matches_fingerprint(junk, "x" * 32) is False


# ============================================================ SEC-04 / F5


def test_setup_enables_auth(client_auth):
    """F5 chain B: setup used to create the user WITHOUT re-enabling auth.

    An anonymous caller disabled auth on a fresh instance, the owner completed
    setup, and the instance stayed open to the LAN with no visible symptom.
    Here the disable is refused outright (see the next test), so this asserts the
    second half: setup itself always leaves auth ON.
    """
    r = client_auth.post(
        "/api/auth/setup", json={"username": "owner", "password": "pw123456"}
    )
    assert r.status_code == 200
    assert r.json()["success"] is True

    status = client_auth.get("/api/auth/status").json()
    assert status["auth_enabled"] is True
    assert status["has_user"] is True


def test_anonymous_cannot_disable_auth_before_setup(client_auth):
    """F5 chain B, step 2: the anonymous pre-setup disable must be refused."""
    before = client_auth.get("/api/auth/status").json()
    assert before["has_user"] is False

    r = client_auth.post("/api/auth/toggle", json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["success"] is False

    after = client_auth.get("/api/auth/status").json()
    assert after["auth_enabled"] is True


def test_toggle_enable_still_refused(client_auth):
    """Unchanged rule: enabling goes through /configure, never /toggle."""
    assert client_auth.post("/api/auth/toggle", json={"enabled": True}).json()["success"] is False


# ============================================================ SEC-05 / F6


def test_configure_requires_current_password(client_auth):
    """F6/F10: a cookie alone must not be enough to rewrite the sole account."""
    client_auth.post("/api/auth/setup", json={"username": "owner", "password": "right-password"})

    r = client_auth.post(
        "/api/auth/configure", json={"username": "attacker", "password": "newpw123"}
    )
    body = r.json()
    assert body["success"] is False
    assert "current password" in body["error"].lower()

    # the original account still works
    login = client_auth.post(
        "/api/auth/login", json={"username": "owner", "password": "right-password"}
    )
    assert login.json()["success"] is True


def test_configure_rejects_wrong_current_password(client_auth):
    client_auth.post("/api/auth/setup", json={"username": "owner", "password": "right-password"})

    r = client_auth.post(
        "/api/auth/configure",
        json={
            "username": "attacker",
            "password": "newpw123",
            "current_password": "wrong-password",
        },
    )
    assert r.json()["success"] is False

    login = client_auth.post(
        "/api/auth/login", json={"username": "owner", "password": "right-password"}
    )
    assert login.json()["success"] is True


def test_configure_works_with_correct_current_password(client_auth):
    """Non-regression: the legitimate credential change still succeeds."""
    client_auth.post("/api/auth/setup", json={"username": "owner", "password": "right-password"})

    r = client_auth.post(
        "/api/auth/configure",
        json={
            "username": "owner2",
            "password": "newpw123",
            "current_password": "right-password",
        },
    )
    assert r.json()["success"] is True

    login = client_auth.post(
        "/api/auth/login", json={"username": "owner2", "password": "newpw123"}
    )
    assert login.json()["success"] is True


def test_first_run_configure_needs_no_current_password(client_auth):
    """First run has no account, so there is no current password to prove."""
    assert client_auth.get("/api/auth/status").json()["has_user"] is False

    r = client_auth.post(
        "/api/auth/configure", json={"username": "owner", "password": "pw123456"}
    )
    assert r.json()["success"] is True
    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is True


# ============================================================ SEC-07 / F11


def test_app_config_get_hides_session_secret(client):
    """F11: the read endpoint served ANY app_config row, session_secret included."""
    body = client.get("/api/system/app-config/session_secret").json()
    assert body["success"] is False
    assert body["error"] == "key_not_allowed"
    assert "value" not in body


@pytest.mark.parametrize(
    "key", ["session_secret", "auth_enabled", "encryption_key", "anything_else"]
)
def test_app_config_get_rejects_keys_outside_the_allow_list(client, key):
    assert client.get(f"/api/system/app-config/{key}").json()["success"] is False


def test_app_config_get_still_serves_allowed_keys(client):
    """Non-regression: the frontend's real keys keep working."""
    body = client.get("/api/system/app-config/currency").json()
    assert body["success"] is True
    assert "value" in body


def test_app_config_read_surface_equals_write_surface():
    """The two allow-lists must not drift apart — they are the same set by design."""
    import inspect

    from backend.api import system_routes

    src = inspect.getsource(system_routes.get_app_config_value)
    assert "_ALLOWED_APP_CONFIG_KEYS" in src
