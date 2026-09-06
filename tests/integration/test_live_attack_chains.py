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


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory):
    """Boot a real uvicorn subprocess on an ephemeral port; always tear it down."""
    data_dir = tmp_path_factory.mktemp("live-server-data")
    port = _free_port()
    env = {
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
    proc = subprocess.Popen(
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
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
                pytest.fail(f"server exited during boot (rc={proc.returncode}):\n{out}")
            try:
                status, _ = _raw_request(port, "/api/health")
                if status == 200:
                    ready = True
                    break
            except OSError:
                pass
            time.sleep(0.25)
        if not ready:
            pytest.fail(f"server did not answer /api/health within {BOOT_TIMEOUT_S}s")
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()
            proc.wait(timeout=10)
        if proc.stdout:
            proc.stdout.close()


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


def _post_json(port: int, path: str, payload: dict) -> tuple[int, bytes, list[str]]:
    """Minimal raw POST returning (status, body, set-cookie headers)."""
    encoded = json.dumps(payload).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(encoded)}\r\n"
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
