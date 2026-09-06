"""Live attack-chain replay — a REAL server, raw HTTP over a socket.

This is the empirical proof Phase 10 is judged on. It boots `backend.main:app`
under uvicorn as a subprocess (temp data dir, demo mode) and speaks raw HTTP so
percent-encoded escapes arrive at the handler exactly as an attacker sends
them — no client library normalises them away first.

Covers:
  * SEC-01 / F1 — pre-auth path traversal in the SPA catch-all.
  * SEC-07 / F11 — `GET /api/system/app-config/{key}` serving the session secret.

Deliberately does NOT use the sync `client` / `client_auth` conftest fixtures:
they drive their own event loop, and this test owns a real process instead.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BOOT_TIMEOUT_S = 30.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _raw_request(port: int, raw_target: str, headers: str = "") -> tuple[int, bytes]:
    """Send a hand-built request line so the target is NOT normalised.

    Returns (status_code, body_bytes).
    """
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        request = (
            f"GET {raw_target} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"{headers}"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("latin-1"))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    payload = b"".join(chunks)
    head, _, body = payload.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n")[0].split(b" ")[1])
    return status, body


def _server_env(data_dir: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(data_dir),
        "IPMIDECK_DEMO": "true",
        "IPMIDECK_DATA_DIR": str(data_dir),
        "IPMIDECK_DATA_DB_PATH": str(data_dir / "test.db"),
        "IPMIDECK_LOGGING_LEVEL": "warning",
        "PYTHONPATH": str(REPO_ROOT),
        "NO_COLOR": "1",
        "TERM": "dumb",
    }


def _spawn_server(data_dir: Path, port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=_server_env(data_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _await_ready(proc: subprocess.Popen, port: int) -> None:
    """Bounded readiness poll against /api/health."""
    deadline = time.monotonic() + BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            pytest.fail(f"server exited during boot (rc={proc.returncode}):\n{out}")
        try:
            status, _ = _raw_request(port, "/api/health")
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(0.25)
    pytest.fail(f"server did not answer /api/health within {BOOT_TIMEOUT_S}s")


def _stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        proc.kill()
        proc.wait(timeout=15)
    if proc.stdout:
        proc.stdout.close()


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory):
    """Boot a real uvicorn subprocess on an ephemeral port; always tear it down."""
    data_dir = tmp_path_factory.mktemp("live-server-data")
    port = _free_port()
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)
        yield port
    finally:
        _stop_server(proc)


@pytest.fixture(scope="module")
def index_html_size(live_server: int) -> int:
    """The byte length of the SPA shell — the "contained" answer for every escape."""
    status, body = _raw_request(live_server, "/")
    assert status == 200
    assert len(body) > 0
    return len(body)


# --- SEC-01 / F1 — pre-auth path traversal --------------------------------

# The first three were verified EXPLOITABLE against this handler before the fix:
# each returned 200 with the 4322-byte pyproject.toml where index.html is 647 bytes.
TRAVERSAL_TARGETS = [
    "/../../pyproject.toml",
    "/%2e%2e%2f%2e%2e%2fpyproject.toml",
    "/..%2f..%2fpyproject.toml",
    "/..%5c..%5cpyproject.toml",
    "/....//....//pyproject.toml",
    "/%2e%2e/%2e%2e/pyproject.toml",
    "/../../backend/main.py",
    "/../../data/ipmideck.db",
    "/../../data/encryption.key",
    "/etc/passwd",
    "/../../../../../../etc/passwd",
]


@pytest.mark.parametrize("target", TRAVERSAL_TARGETS)
def test_traversal_returns_spa_not_the_target_file(
    live_server: int, index_html_size: int, target: str
) -> None:
    """Every escaping spelling must return the SPA shell, byte-for-byte."""
    status, body = _raw_request(live_server, target)
    assert status == 200, f"{target} -> HTTP {status}"
    assert len(body) == index_html_size, (
        f"{target} returned {len(body)} bytes, expected the {index_html_size}-byte "
        f"index.html — content leaked outside the web root"
    )


@pytest.mark.parametrize("target", TRAVERSAL_TARGETS)
def test_traversal_body_contains_no_out_of_root_content(live_server: int, target: str) -> None:
    """Belt-and-braces: no fingerprint of a real out-of-root file in the body."""
    _, body = _raw_request(live_server, target)
    lowered = body.lower()
    for marker in (b"[project]", b"[tool.", b"root:x:", b"def _mount_spa", b"sqlite format"):
        assert marker not in lowered, f"{target} leaked {marker!r}"


def test_unmatched_api_path_still_404s(live_server: int) -> None:
    """FIX-04 disabled-module contract: unmatched /api/* is 404, never the SPA."""
    for target in ("/api/nonexistent-xyz", "/api/modules/disabled/foo", "/api/"):
        status, _ = _raw_request(live_server, target)
        assert status == 404, f"{target} -> HTTP {status}, expected 404"


def test_nul_byte_path_does_not_500(live_server: int, index_html_size: int) -> None:
    """Path.resolve() raises ValueError on a NUL byte — it must be caught."""
    status, body = _raw_request(live_server, "/%00x")
    assert status == 200
    assert len(body) == index_html_size


def test_over_long_path_does_not_500(live_server: int, index_html_size: int) -> None:
    status, body = _raw_request(live_server, "/" + "a" * 5000)
    assert status == 200
    assert len(body) == index_html_size


def test_root_serves_the_spa(live_server: int, index_html_size: int) -> None:
    status, body = _raw_request(live_server, "/")
    assert status == 200
    assert b"<div id=\"root\">" in body or b"<div id='root'>" in body
    assert len(body) == index_html_size


def test_client_side_route_serves_the_spa(live_server: int, index_html_size: int) -> None:
    status, body = _raw_request(live_server, "/dashboard")
    assert status == 200
    assert len(body) == index_html_size


# --- SEC-07 / F11 — app-config read path ----------------------------------

SECRET_KEYS = ["session_secret", "app_secret", "auth_enabled", "encryption_key"]


def _post_json(port: int, path: str, payload: dict, headers: str = "") -> tuple[int, bytes, list[str]]:
    """Minimal raw POST returning (status, body, set-cookie headers)."""
    encoded = json.dumps(payload).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(encoded)}\r\n"
            f"{headers}"
            "Connection: close\r\n\r\n"
        ).encode() + encoded
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    payload_bytes = b"".join(chunks)
    head, _, body = payload_bytes.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    cookies = [ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("set-cookie:")]
    return status, body, cookies


@pytest.fixture(scope="module")
def session_cookie(live_server: int) -> str:
    """A REAL authenticated session, obtained over HTTP like any client."""
    status, _, cookies = _post_json(
        live_server,
        "/api/auth/setup",
        {"username": "sec07admin", "password": "correct-horse-battery-staple"},
    )
    assert status == 200, f"setup failed with HTTP {status}"
    assert cookies, "setup returned no session cookie"
    return cookies[0].split(";")[0]


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_app_config_refuses_secret_keys_unauthenticated(live_server: int, key: str) -> None:
    """No caller without a session gets a secret out of the read path."""
    status, body = _raw_request(live_server, f"/api/system/app-config/{key}")
    assert status in (401, 200)
    assert b"key_not_allowed" in body or b"unauthorized" in body.lower()
    parsed = json.loads(body)
    assert parsed.get("value") in (None, ""), f"{key} leaked a value: {parsed}"


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_app_config_refuses_secret_keys_authenticated(
    live_server: int, session_cookie: str, key: str
) -> None:
    """A fully authenticated caller must not be able to name a secret key either."""
    status, body = _raw_request(
        live_server,
        f"/api/system/app-config/{key}",
        headers=f"Cookie: {session_cookie}\r\n",
    )
    assert status == 200, f"HTTP {status}"
    parsed = json.loads(body)
    assert parsed.get("success") is False, f"{key} was served: {parsed}"
    assert parsed.get("error") == "key_not_allowed"
    assert "value" not in parsed, f"{key} leaked a value: {parsed}"


@pytest.mark.parametrize(
    "key",
    [
        "currency",
        "alerting.notifications_enabled",
        "data.retention_days",
        "fanpilot.auto_recover_on_offline",
        "fanpilot.resume_threshold_seconds",
        "fanpilot.failsafe_mode",
        "fanpilot.failsafe_speed",
    ],
)
def test_allow_listed_keys_still_resolve(
    live_server: int, session_cookie: str, key: str
) -> None:
    """The keys the SPA actually reads must keep working (missing row -> value=None)."""
    status, body = _raw_request(
        live_server,
        f"/api/system/app-config/{key}",
        headers=f"Cookie: {session_cookie}\r\n",
    )
    assert status == 200
    parsed = json.loads(body)
    assert parsed.get("success") is True, f"{key} was refused: {parsed}"
    assert parsed.get("key") == key
    assert "value" in parsed


# --- SEC-02 / F2 — stop-rotate-restart evicts every cookie -----------------


def _rotate_secret_via_cli(data_dir: Path) -> None:
    """Run the operator's actual eviction move against the same on-disk DB."""
    result = subprocess.run(
        [sys.executable, "-m", "backend.main", "rotate-session-secret"],
        cwd=str(REPO_ROOT),
        env=_server_env(data_dir),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"rotate-session-secret exited {result.returncode}: "
        f"{result.stdout.decode(errors='replace')}{result.stderr.decode(errors='replace')}"
    )
    assert b"rotated" in result.stdout.lower()


def test_stop_rotate_restart_refuses_the_retained_cookie(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """ROADMAP criterion 3: a token minted from a copied DB dies on rotation.

    Replayed as the operator actually performs it, because the running process
    holds the secret in memory:

        1. stop IPMIDeck
        2. ipmideck rotate-session-secret
        3. start IPMIDeck

    This is the exact sequence 10-03 documents in README's Security section.
    """
    data_dir = tmp_path_factory.mktemp("rotate-chain")
    port = _free_port()

    # --- boot, create an account, keep the cookie
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)
        status, _, cookies = _post_json(
            port,
            "/api/auth/setup",
            {"username": "rotateop", "password": "correct-horse-battery-staple"},
        )
        assert status == 200 and cookies
        cookie = cookies[0].split(";")[0]

        # The cookie works before rotation.
        status, body = _raw_request(port, "/api/servers", headers=f"Cookie: {cookie}\r\n")
        assert status == 200, f"baseline: authenticated request failed with {status}"
        status, body = _raw_request(port, "/api/auth/me", headers=f"Cookie: {cookie}\r\n")
        assert json.loads(body).get("authenticated") is True
    finally:
        # --- step 1: stop
        _stop_server(proc)

    # --- step 2: rotate against the same on-disk DB
    _rotate_secret_via_cli(data_dir)

    # --- step 3: restart on the same data dir
    port2 = _free_port()
    proc2 = _spawn_server(data_dir, port2)
    try:
        _await_ready(proc2, port2)

        status, _ = _raw_request(port2, "/api/servers", headers=f"Cookie: {cookie}\r\n")
        assert status == 401, (
            f"the pre-rotation cookie still authenticated after the rotation (HTTP {status})"
        )

        status, body = _raw_request(port2, "/api/auth/me", headers=f"Cookie: {cookie}\r\n")
        assert status == 200
        assert json.loads(body).get("authenticated") is False

        # And the operator can log straight back in with the same password.
        status, _, cookies = _post_json(
            port2,
            "/api/auth/login",
            {"username": "rotateop", "password": "correct-horse-battery-staple"},
        )
        assert status == 200 and cookies
        fresh = cookies[0].split(";")[0]
        status, _ = _raw_request(port2, "/api/servers", headers=f"Cookie: {fresh}\r\n")
        assert status == 200, "a freshly issued cookie must work after rotation"
    finally:
        _stop_server(proc2)


# --- SEC-03 / F7 — a password change evicts every session -----------------


def test_password_change_evicts_the_retained_cookie(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """ROADMAP criterion 4, over real HTTP: the advertised eviction move evicts.

    Chain D's counter-proof. `/configure` changes the account password; the
    cookie held from before the change must be refused on a protected route AND
    on `/api/auth/me`, and the newly issued cookie must work.
    """
    data_dir = tmp_path_factory.mktemp("pwchange-chain")
    port = _free_port()
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)
        status, _, cookies = _post_json(
            port,
            "/api/auth/setup",
            {"username": "changeop", "password": "original-password-value"},
        )
        assert status == 200 and cookies
        old_cookie = cookies[0].split(";")[0]

        status, _ = _raw_request(port, "/api/servers", headers=f"Cookie: {old_cookie}\r\n")
        assert status == 200, "baseline: the cookie must work before the change"

        # Change the password through the real endpoint, carrying the session.
        # SEC-05 (Plan 03) additionally requires the current password here.
        status, _, new_cookies = _post_json(
            port,
            "/api/auth/configure",
            {
                "username": "changeop",
                "password": "a-brand-new-password",
                "current_password": "original-password-value",
            },
            headers=f"Cookie: {old_cookie}\r\n",
        )
        assert status == 200

        # The OLD cookie is dead everywhere.
        status, _ = _raw_request(port, "/api/servers", headers=f"Cookie: {old_cookie}\r\n")
        assert status == 401, f"pre-change cookie still accepted on a protected route ({status})"

        status, body = _raw_request(port, "/api/auth/me", headers=f"Cookie: {old_cookie}\r\n")
        assert status == 200
        assert json.loads(body).get("authenticated") is False, "/api/auth/me still accepts it"

        # The cookie issued by /configure works.
        assert new_cookies, "/configure must issue a fresh cookie"
        fresh = new_cookies[0].split(";")[0]
        status, _ = _raw_request(port, "/api/servers", headers=f"Cookie: {fresh}\r\n")
        assert status == 200, "the freshly issued cookie must authenticate"
    finally:
        _stop_server(proc)


def test_claimless_forged_cookie_is_refused_over_http(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """D1 fail-closed at the route layer: a perfectly-signed claim-less token.

    Built the way an attacker with the stolen signing secret would: read the
    secret out of the DB, mint a token with a valid signature and no `cfp`
    claim — indistinguishable from a pre-upgrade cookie. It must be refused.
    """
    import base64
    import hashlib
    import hmac
    import sqlite3
    import time as _time

    data_dir = tmp_path_factory.mktemp("forge-chain")
    port = _free_port()
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)
        status, _, cookies = _post_json(
            port,
            "/api/auth/setup",
            {"username": "forgeop", "password": "correct-horse-battery-staple"},
        )
        assert status == 200 and cookies

        # Attacker reads the signing secret from the (copied) database.
        conn = sqlite3.connect(str(data_dir / "test.db"))
        secret = conn.execute(
            "SELECT value FROM app_config WHERE key='session_secret'"
        ).fetchone()[0]
        conn.close()
        assert secret

        payload = json.dumps(
            {"sub": "forgeop", "iat": int(_time.time()), "exp": int(_time.time()) + 86400},
            separators=(",", ":"),
        )
        sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        forged = f"session={b64}.{sig}"

        status, _ = _raw_request(port, "/api/servers", headers=f"Cookie: {forged}\r\n")
        assert status == 401, f"a claim-less forged cookie was accepted (HTTP {status})"

        status, body = _raw_request(port, "/api/auth/me", headers=f"Cookie: {forged}\r\n")
        assert json.loads(body).get("authenticated") is False
    finally:
        _stop_server(proc)


# --- SEC-04 clause 2 / SEC-05 — Chain B and Chain D, live -----------------


def test_chain_b_end_state_is_closed_live(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Chain B replayed against a real server: anonymous toggle -> setup -> 401.

    Verified live in this tree BEFORE the fix, this exact sequence ended in a
    **200** with the full server inventory. It must now end in a 401.

    The assertion is on the END STATE, not on the toggle. The anonymous
    pre-setup disable is STILL EXPECTED TO SUCCEED — that is SEC-04 clause 1,
    deferred onto SEC-06 per D4, and refusing it would break the
    SAFETY-CRITICAL first-run skip in SetupPage.tsx:101.
    """
    data_dir = tmp_path_factory.mktemp("chain-b")
    port = _free_port()
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)

        # Step 1 — anonymous disable. Accepted by design (clause 1, deferred).
        status, body, _ = _post_json(port, "/api/auth/toggle", {"enabled": False})
        assert status == 200
        assert json.loads(body).get("success") is True, (
            "the first-run skip path must keep working — refusing it is a permanent lockout"
        )

        # Step 2 — the real operator completes first run.
        status, _, cookies = _post_json(
            port,
            "/api/auth/setup",
            {"username": "chainbop", "password": "correct-horse-battery-staple"},
        )
        assert status == 200 and cookies

        # Step 3 — an ANONYMOUS caller (no cookie) hits a protected route.
        status, _ = _raw_request(port, "/api/servers")
        assert status == 401, (
            f"Chain B still ends open: anonymous /api/servers returned {status}, expected 401"
        )

        status, body = _raw_request(port, "/api/auth/status")
        assert json.loads(body).get("auth_enabled") is True
    finally:
        _stop_server(proc)


def test_chain_d_stale_cookie_cannot_seize_the_account_live(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """SEC-05 over real HTTP: a stale-but-signed cookie cannot rewrite the account.

    This is the takeover that defeats incident response — /configure is exactly
    what an operator uses to evict an attacker.
    """
    data_dir = tmp_path_factory.mktemp("chain-d")
    port = _free_port()
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)
        status, _, cookies = _post_json(
            port,
            "/api/auth/setup",
            {"username": "chaindop", "password": "original-password-value"},
        )
        assert status == 200 and cookies
        stale = cookies[0].split(";")[0]

        # The operator rotates credentials; the held cookie goes stale.
        status, _, _ = _post_json(
            port,
            "/api/auth/configure",
            {
                "username": "chaindop",
                "password": "a-brand-new-password",
                "current_password": "original-password-value",
            },
            headers=f"Cookie: {stale}\r\n",
        )
        assert status == 200

        # The attacker replays the stale cookie against the takeover endpoint.
        status, body, _ = _post_json(
            port,
            "/api/auth/configure",
            {
                "username": "attacker",
                "password": "attacker-password",
                "current_password": "a-brand-new-password",
            },
            headers=f"Cookie: {stale}\r\n",
        )
        assert status == 401, f"a stale cookie seized /configure (HTTP {status})"

        # And with no cookie at all.
        status, body, _ = _post_json(
            port,
            "/api/auth/configure",
            {"username": "attacker", "password": "attacker-password"},
        )
        assert status == 401 or json.loads(body).get("success") is False

        # The real operator's new credentials still work.
        status, _, cookies = _post_json(
            port,
            "/api/auth/login",
            {"username": "chaindop", "password": "a-brand-new-password"},
        )
        assert status == 200 and cookies
        fresh = cookies[0].split(";")[0]
        status, _ = _raw_request(port, "/api/servers", headers=f"Cookie: {fresh}\r\n")
        assert status == 200
    finally:
        _stop_server(proc)


def test_configure_requires_the_current_password_live(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Even a VALID session cannot rewrite the account without the password."""
    data_dir = tmp_path_factory.mktemp("sec05-live")
    port = _free_port()
    proc = _spawn_server(data_dir, port)
    try:
        _await_ready(proc, port)
        status, _, cookies = _post_json(
            port,
            "/api/auth/setup",
            {"username": "sec05op", "password": "original-password-value"},
        )
        assert status == 200 and cookies
        cookie = cookies[0].split(";")[0]

        status, body, _ = _post_json(
            port,
            "/api/auth/configure",
            {"username": "attacker", "password": "attacker-password"},
            headers=f"Cookie: {cookie}\r\n",
        )
        assert status == 200
        assert json.loads(body).get("success") is False, (
            "a valid session alone still rewrote the account"
        )

        # The original account is untouched.
        status, body, _ = _post_json(
            port,
            "/api/auth/login",
            {"username": "sec05op", "password": "original-password-value"},
        )
        assert json.loads(body).get("success") is True
    finally:
        _stop_server(proc)

