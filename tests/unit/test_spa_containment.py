"""SEC-01/F1 — containment tests for the SPA catch-all.

The shipped handler joined user input onto the static root and served whatever
``is_file()`` accepted, so an UNAUTHENTICATED request could read
``../../data/encryption.key`` and ``../../data/ipmideck.db`` — i.e. the AES key
and the database holding BMC root credentials.

Two layers are asserted here:

1. ``_resolve_spa_file`` (pure, deterministic): every escape spelling must return
   None, and legitimate in-root files must still resolve.
2. The live route: ``/api/*`` must still 404 (the FIX-04 disabled-module contract
   that the naive patch silently breaks), and traversal must fall back to the SPA.

asyncio_mode="auto" is set project-wide, so async tests need no decorator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.main import _resolve_spa_file

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def spa_root(tmp_path: Path) -> Path:
    """A throwaway static root with one legitimate file, plus a secret OUTSIDE it."""
    root = tmp_path / "static"
    root.mkdir()
    (root / "index.html").write_text("<html>spa</html>")
    (root / "favicon.svg").write_text("<svg/>")
    assets = root / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("console.log(1)")

    # The prize: a file one level ABOVE the root, mirroring data/encryption.key.
    (tmp_path / "encryption.key").write_bytes(b"\x00" * 32)
    (tmp_path / "ipmideck.db").write_bytes(b"SQLite format 3\x00")
    return root.resolve()


# ------------------------------------------------- containment (the fix)


@pytest.mark.parametrize(
    "evil",
    [
        "../encryption.key",
        "../ipmideck.db",
        "../../etc/passwd",
        "....//....//encryption.key",
        "..%2f..%2fencryption.key",
        "%2e%2e%2f%2e%2e%2fencryption.key",
        "..\\..\\encryption.key",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "/C:/Windows/win.ini",
        "//host/share/file",
        "a" * 5000,
        "x\x00.js",
        "../" * 40 + "encryption.key",
    ],
)
def test_traversal_is_contained(spa_root: Path, evil: str) -> None:
    """Every escape spelling resolves to None -> the caller serves index.html."""
    assert _resolve_spa_file(evil, spa_root) is None


def test_empty_path_falls_back(spa_root: Path) -> None:
    assert _resolve_spa_file("", spa_root) is None


def test_directory_is_not_served(spa_root: Path) -> None:
    """A directory exists but is not a file -> fall back, never a 500."""
    assert _resolve_spa_file("assets", spa_root) is None


def test_missing_file_falls_back(spa_root: Path) -> None:
    assert _resolve_spa_file("nope.js", spa_root) is None


# ------------------------------------------------- legitimate files still work


@pytest.mark.parametrize("good", ["favicon.svg", "index.html", "assets/app.js"])
def test_real_files_are_served(spa_root: Path, good: str) -> None:
    hit = _resolve_spa_file(good, spa_root)
    assert hit is not None
    assert hit.is_file()
    assert hit.is_relative_to(spa_root)


def test_symlink_escape_is_contained(spa_root: Path) -> None:
    """resolve() collapses symlinks, so a symlinked escape is contained too."""
    target = spa_root.parent / "encryption.key"
    link = spa_root / "sneaky.js"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks not supported here")
    assert _resolve_spa_file("sneaky.js", spa_root) is None


# ------------------------------------------------- the guard that must NOT regress


def test_api_guard_is_retained() -> None:
    """/api/* must 404, not fall through to the SPA (FIX-04 disabled-module contract).

    The patch proposed in the audit dropped this guard; with it removed,
    /api/health answered 200 index.html instead of 404. Asserted on the real
    handler source so a future refactor cannot silently delete it.
    """
    import inspect

    from backend.main import _mount_spa

    source = inspect.getsource(_mount_spa)
    assert 'full_path.startswith("api/")' in source
    assert "status_code=404" in source
