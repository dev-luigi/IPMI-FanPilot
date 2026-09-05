"""SEC-02/F2 — session-secret rotation.

Session tokens are stateless HMACs signed with ``app_config['session_secret']``,
which lived in the same database SEC-01 let an unauthenticated caller read. Anyone
holding a copy keeps minting valid cookies after the traversal is patched, so the
advisory needs a supported eviction step. There was none.

Covered here:
- the secret really changes in the database
- a token signed with the OLD secret stops verifying once a fresh manager loads
  the new one (i.e. after the restart the CLI demands)
- the CLI wiring: subcommand parses, ``--yes``/``-y`` is accepted, declining the
  prompt changes nothing

asyncio_mode="auto" is project-wide, so async tests need no decorator.
"""

from __future__ import annotations

import pytest

from backend.core.auth import AuthManager


# ----------------------------------------------------------- rotation itself


async def test_rotation_changes_the_stored_secret(auth_manager):
    am, db = auth_manager
    before = await db.get_config("session_secret")
    assert before

    returned = await am.rotate_session_secret()

    after = await db.get_config("session_secret")
    assert after == returned
    assert after != before
    assert len(after) == 64  # token_hex(32)


async def test_rotation_is_not_idempotent(auth_manager):
    """Two rotations must yield two different secrets."""
    am, _db = auth_manager
    first = await am.rotate_session_secret()
    second = await am.rotate_session_secret()
    assert first != second


async def test_old_token_dies_after_restart(auth_manager):
    """A token signed with the old secret must fail once the new one is loaded.

    The running manager keeps the old secret in memory on purpose (that is why the
    CLI shouts about restarting), so the post-restart state is modelled by building
    a second AuthManager over the same database.
    """
    am, db = auth_manager
    await am.create_user("alice", "pw")
    token = am.create_session_token("alice")
    assert am.verify_session_token(token) == "alice"

    await am.rotate_session_secret()

    # Same process, secret still cached in memory -> token still valid.
    assert am.verify_session_token(token) == "alice"

    # After a restart a fresh manager loads the rotated secret -> token rejected.
    restarted = AuthManager(db)
    await restarted.initialize()
    assert restarted.verify_session_token(token) is None


async def test_new_token_works_after_rotation(auth_manager):
    """Rotation must not break the ability to issue fresh sessions."""
    am, db = auth_manager
    await am.create_user("alice", "pw")
    await am.rotate_session_secret()

    restarted = AuthManager(db)
    await restarted.initialize()
    fresh = restarted.create_session_token("alice")
    assert restarted.verify_session_token(fresh) == "alice"


# ----------------------------------------------------------- CLI wiring


def test_cli_parses_rotate_subcommand():
    from backend.main import _build_arg_parser

    args = _build_arg_parser().parse_args(["rotate-session-secret"])
    assert args.command == "rotate-session-secret"
    assert args.yes is False


@pytest.mark.parametrize("flag", ["--yes", "-y"])
def test_cli_accepts_yes_flag(flag):
    from backend.main import _build_arg_parser

    args = _build_arg_parser().parse_args(["rotate-session-secret", flag])
    assert args.yes is True


def test_declining_the_prompt_changes_nothing(monkeypatch):
    """Answering anything but y/yes must abort BEFORE touching the database."""
    import backend.main as main_mod

    monkeypatch.setattr("builtins.input", lambda *_: "n")

    def _boom(*_a, **_kw):  # pragma: no cover - must never run
        raise AssertionError("the database was opened despite the operator declining")

    monkeypatch.setattr(main_mod, "Database", _boom)

    with pytest.raises(SystemExit) as exc:
        main_mod._rotate_session_secret(assume_yes=False)
    assert exc.value.code == 1


def test_restart_warning_is_printed(monkeypatch, capsys):
    """The restart warning is the whole point of the CLI-only design — assert it."""
    import backend.main as main_mod

    async def _fake_rotate():
        return ("old" * 21, "new" * 21)

    monkeypatch.setattr(main_mod.asyncio, "run", lambda _coro: ("oldsecret", "newsecret"))
    main_mod._rotate_session_secret(assume_yes=True)

    out = capsys.readouterr().out
    assert "RESTART IPMIDECK NOW" in out
    assert "Session secret rotated." in out
    # the advisory's other two steps must be named
    assert "credential key" in out
    assert "BMC credentials" in out


def test_secret_is_never_printed(monkeypatch, capsys):
    """The rotated secret must not leak into stdout."""
    import backend.main as main_mod

    monkeypatch.setattr(
        main_mod.asyncio, "run", lambda _coro: ("0" * 64, "deadbeef" * 8)
    )
    main_mod._rotate_session_secret(assume_yes=True)

    out = capsys.readouterr().out
    assert "deadbeef" not in out
