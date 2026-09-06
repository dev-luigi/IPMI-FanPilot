"""SEC-04 / SEC-05 route-level hardening tests (Phase 10, Plan 03).

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
