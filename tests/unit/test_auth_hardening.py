"""SEC-04 / SEC-05 route-level hardening tests.

Everything here goes through HTTP with the synchronous `client_auth` fixture —
never `await bm.auth...` — because those fixtures drive their own event loop
(prior-findings trap 6).

Scope note, deliberate: there is NO test asserting that an anonymous
`POST /api/auth/toggle {enabled:false}` is refused on a fresh instance. Per D4
that is SEC-04 **clause 1**, which is deferred onto SEC-06 — before any
credential exists nothing over HTTP separates the first-run operator from a LAN
attacker. The test below asserts the opposite (that it still SUCCEEDS), because
`SetupPage.tsx:101` depends on it and refusing it is a permanent lockout.
"""

from __future__ import annotations

SETUP_USER = "phase10admin"
SETUP_PASS = "correct-horse-battery-staple"


# --- SEC-04 clause 2 (F5) -------------------------------------------------


def test_first_run_skip_on_an_empty_instance_still_succeeds(client_auth):
    """SAFETY-CRITICAL regression guard for the SetupPage "No" branch.

    `SetupPage.tsx:101` calls this endpoint anonymously and `auth_enabled`
    defaults to "true", so a frontend-only skip would leave auth on with no
    user = permanent lockout. This passes on today's code and must keep
    passing; it is the guard that catches any future attempt to bolt a refusal
    onto this path.

    It also passes under the demo-seeded fixture (six servers, no account)
    precisely because no servers-emptiness condition was added — such a guard
    would fire against the legitimate operator, not the attacker.
    """
    r = client_auth.post("/api/auth/toggle", json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["success"] is True

    status = client_auth.get("/api/auth/status").json()
    assert status["auth_enabled"] is False
    assert status["has_user"] is False


def test_setup_re_enables_auth_after_an_anonymous_skip(client_auth):
    """SEC-04 clause 2: completing first run always re-closes the instance."""
    client_auth.post("/api/auth/toggle", json={"enabled": False})
    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is False

    r = client_auth.post(
        "/api/auth/setup", json={"username": SETUP_USER, "password": SETUP_PASS}
    )
    assert r.status_code == 200 and r.json()["success"] is True

    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is True


def test_chain_b_end_state_is_closed(client_auth):
    """Anonymous toggle-off -> setup -> anonymous protected request = 401.

    The middle step is still accepted (clause 1, deferred). What changed is
    that it no longer SURVIVES setup: before this phase the instance stayed
    open forever with no UI symptom.
    """
    client_auth.post("/api/auth/toggle", json={"enabled": False})
    client_auth.post(
        "/api/auth/setup", json={"username": SETUP_USER, "password": SETUP_PASS}
    )
    # Drop the cookie /setup issued — we are asking what an ANONYMOUS caller sees.
    client_auth.cookies.clear()

    r = client_auth.get("/api/servers")
    assert r.status_code == 401, f"instance still open to anonymous callers ({r.status_code})"


def test_setup_leaves_auth_enabled_on_a_normal_first_run(client_auth):
    """The flag was never touched beforehand — setup must still leave it on."""
    r = client_auth.post(
        "/api/auth/setup", json={"username": SETUP_USER, "password": SETUP_PASS}
    )
    assert r.status_code == 200 and r.json()["success"] is True
    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is True


# --- SEC-05 (F6 + F10) ----------------------------------------------------


def _setup_account(client) -> None:
    r = client.post("/api/auth/setup", json={"username": SETUP_USER, "password": SETUP_PASS})
    assert r.status_code == 200 and r.json()["success"] is True


def test_configure_without_current_password_is_refused(client_auth):
    """An account exists: rewriting it requires proving knowledge of the password."""
    _setup_account(client_auth)

    r = client_auth.post(
        "/api/auth/configure", json={"username": "attacker", "password": "attacker-password"}
    )
    assert r.status_code == 200
    assert r.json()["success"] is False

    # The account is unchanged: the original credentials still authenticate.
    client_auth.cookies.clear()
    login = client_auth.post(
        "/api/auth/login", json={"username": SETUP_USER, "password": SETUP_PASS}
    )
    assert login.json()["success"] is True


def test_configure_with_a_wrong_current_password_is_refused(client_auth):
    _setup_account(client_auth)

    r = client_auth.post(
        "/api/auth/configure",
        json={
            "username": "attacker",
            "password": "attacker-password",
            "current_password": "not-the-password",
        },
    )
    assert r.status_code == 200
    assert r.json()["success"] is False

    client_auth.cookies.clear()
    login = client_auth.post(
        "/api/auth/login", json={"username": SETUP_USER, "password": SETUP_PASS}
    )
    assert login.json()["success"] is True


def test_configure_with_the_correct_current_password_succeeds(client_auth):
    _setup_account(client_auth)

    r = client_auth.post(
        "/api/auth/configure",
        json={
            "username": "newadmin",
            "password": "a-brand-new-password",
            "current_password": SETUP_PASS,
        },
    )
    assert r.status_code == 200
    assert r.json()["success"] is True

    client_auth.cookies.clear()
    login = client_auth.post(
        "/api/auth/login", json={"username": "newadmin", "password": "a-brand-new-password"}
    )
    assert login.json()["success"] is True


def test_configure_is_gated_even_when_auth_is_disabled(client_auth):
    """The F10 window — and the case the SEC-06 deferral rests on.

    An auth-DISABLED instance that still HAS an account could be seized with no
    cookie at all. The gate keys on has_user(), not on auth_enabled, which is
    the only keying that closes this.
    """
    _setup_account(client_auth)

    # Disable auth the legitimate way (session + current password).
    off = client_auth.post(
        "/api/auth/toggle", json={"enabled": False, "current_password": SETUP_PASS}
    )
    assert off.json()["success"] is True
    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is False

    # Now an anonymous caller tries to seize the account.
    client_auth.cookies.clear()
    r = client_auth.post(
        "/api/auth/configure", json={"username": "attacker", "password": "attacker-password"}
    )
    assert r.status_code == 200
    assert r.json()["success"] is False, "F10 window still open on an auth-disabled instance"

    # And with the correct current password it still works for the real operator.
    ok = client_auth.post(
        "/api/auth/configure",
        json={
            "username": "realadmin",
            "password": "a-brand-new-password",
            "current_password": SETUP_PASS,
        },
    )
    assert ok.json()["success"] is True


def test_configure_on_an_account_less_instance_needs_no_current_password(client_auth):
    """Genuine first run: nothing to prove, and the form must still work."""
    client_auth.post("/api/auth/toggle", json={"enabled": False})
    assert client_auth.get("/api/auth/status").json()["has_user"] is False

    r = client_auth.post(
        "/api/auth/configure", json={"username": "firstadmin", "password": "first-password"}
    )
    assert r.status_code == 200
    assert r.json()["success"] is True
    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is True


def test_stale_cookie_is_refused_by_configure(client_auth):
    """Chain D: a signed-but-stale cookie must not rewrite the account."""
    _setup_account(client_auth)
    stale = dict(client_auth.cookies)

    # Rotate the credentials legitimately; the held cookie goes stale.
    client_auth.post(
        "/api/auth/configure",
        json={
            "username": "newadmin",
            "password": "a-brand-new-password",
            "current_password": SETUP_PASS,
        },
    )

    client_auth.cookies.clear()
    r = client_auth.post(
        "/api/auth/configure",
        json={
            "username": "attacker",
            "password": "attacker-password",
            "current_password": "a-brand-new-password",
        },
        cookies=stale,
    )
    assert r.status_code == 401, "a stale cookie was accepted by /configure"


def test_stale_cookie_is_refused_by_toggle(client_auth):
    """The same helper guards /toggle — a stale cookie cannot disable auth."""
    _setup_account(client_auth)
    stale = dict(client_auth.cookies)

    client_auth.post(
        "/api/auth/configure",
        json={
            "username": "newadmin",
            "password": "a-brand-new-password",
            "current_password": SETUP_PASS,
        },
    )

    client_auth.cookies.clear()
    r = client_auth.post(
        "/api/auth/toggle",
        json={"enabled": False, "current_password": "a-brand-new-password"},
        cookies=stale,
    )
    assert r.status_code == 401, "a stale cookie was accepted by /toggle"
    assert client_auth.get("/api/auth/status").json()["auth_enabled"] is True
