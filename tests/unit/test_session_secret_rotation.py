"""SEC-02 / SEC-03 / F17 — manager-level proofs via the async `auth_manager` fixture.

Split by subject:
  * rotation of the session signing secret (SEC-02 / F2)
  * binding session tokens to a credential fingerprint, fail-closed (SEC-03 / F7)
  * `update_password` reporting honestly when it changed nothing (F17)

Manager level on purpose: the fail-closed rule has to be proven at the source, not
only at one route. The route-level half runs over real HTTP in
`tests/integration/test_live_attack_chains.py`. The sync `client` / `client_auth`
fixtures are NOT used here — they drive their own event loop (prior-findings trap 6).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

USERNAME = "operator"
PASSWORD = "correct-horse-battery-staple"


async def _make_user(am, username: str = USERNAME, password: str = PASSWORD) -> None:
    await am.create_user(username, password)


def _decode_payload(token: str) -> dict:
    b64_part, _, _sig = token.rpartition(".")
    return json.loads(base64.urlsafe_b64decode(b64_part + "=" * (-len(b64_part) % 4)))


def _resign(am, payload: dict) -> str:
    """Re-sign a hand-edited payload with the manager's CURRENT secret.

    This is exactly what an attacker holding a stolen signing secret can do, so a
    token built here is indistinguishable from a forged one on the signature.
    """
    data = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(am._secret.encode(), data.encode(), hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")
    return f"{b64}.{sig}"


# --- SEC-02 / F2 — rotatable signing secret --------------------------------


async def test_rotation_replaces_the_stored_secret(auth_manager) -> None:
    am, db = auth_manager
    before = await db.get_config("session_secret")
    assert before
    new = await am.rotate_session_secret()
    after = await db.get_config("session_secret")
    assert after == new
    assert after != before
    assert am._secret == after, "a running process must pick the new secret up immediately"


async def test_token_minted_before_rotation_stops_verifying(auth_manager) -> None:
    """The copied-database case: a token minted under the OLD secret dies on rotation."""
    am, _db = auth_manager
    await _make_user(am)
    token = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(token) == USERNAME

    await am.rotate_session_secret()

    assert await am.verify_session_token_async(token) is None
    assert am.verify_session_token(token) is None


async def test_token_minted_after_rotation_verifies(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    await am.rotate_session_secret()
    token = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(token) == USERNAME


async def test_rotation_is_idempotent_and_always_evicts(auth_manager) -> None:
    am, db = auth_manager
    await _make_user(am)
    first = await am.rotate_session_secret()
    token = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(token) == USERNAME

    second = await am.rotate_session_secret()
    assert second != first
    assert await db.get_config("session_secret") == second
    assert await am.verify_session_token_async(token) is None


async def test_rotation_does_not_touch_the_at_rest_credential_key(auth_manager) -> None:
    """Rotating the session secret must not re-key stored BMC credentials."""
    am, _db = auth_manager
    key_before = am.get_encryption_key()
    await am.rotate_session_secret()
    assert am.get_encryption_key() == key_before


# --- SEC-03 / F7 — credential fingerprint, fail-closed ---------------------


async def test_fresh_token_verifies(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    token = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(token) == USERNAME


async def test_token_carries_the_fingerprint_claim(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    payload = _decode_payload(await am.create_session_token_async(USERNAME))
    assert payload.get("cfp"), "the minted token must carry the cfp claim"
    assert payload["sub"] == USERNAME


async def test_password_change_invalidates_existing_tokens(auth_manager) -> None:
    """SEC-03: the operator's advertised eviction move finally evicts."""
    am, _db = auth_manager
    await _make_user(am)
    token = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(token) == USERNAME

    assert await am.update_password(USERNAME, "a-brand-new-password") is True

    assert await am.verify_session_token_async(token) is None


async def test_new_token_after_password_change_works(auth_manager) -> None:
    """The operator must be able to log straight back in."""
    am, _db = auth_manager
    await _make_user(am)
    await am.update_password(USERNAME, "a-brand-new-password")
    fresh = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(fresh) == USERNAME


async def test_claimless_token_is_rejected_fail_closed(auth_manager) -> None:
    """A correctly-signed token with no cfp claim is REFUSED.

    This is both the pre-upgrade token and the forged token — they are
    byte-indistinguishable on this point, which is why absence cannot mean
    acceptable.
    """
    am, _db = auth_manager
    await _make_user(am)
    token = await am.create_session_token_async(USERNAME)
    payload = _decode_payload(token)
    payload.pop("cfp")
    stripped = _resign(am, payload)

    # The signature itself is perfectly valid — proving the rejection is the
    # claim rule and not a signature failure.
    assert am.verify_session_token(stripped) == USERNAME
    assert await am.verify_session_token_async(stripped) is None


async def test_legacy_synchronous_token_is_rejected(auth_manager) -> None:
    """A token minted by the pre-change synchronous minter carries no claim."""
    am, _db = auth_manager
    await _make_user(am)
    legacy = am.create_session_token(USERNAME)
    assert am.verify_session_token(legacy) == USERNAME  # signature is fine
    assert await am.verify_session_token_async(legacy) is None  # but refused


async def test_wrong_fingerprint_claim_is_rejected(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    payload = _decode_payload(await am.create_session_token_async(USERNAME))
    payload["cfp"] = "0" * 16
    assert await am.verify_session_token_async(_resign(am, payload)) is None


async def test_empty_fingerprint_claim_is_rejected(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    payload = _decode_payload(await am.create_session_token_async(USERNAME))
    payload["cfp"] = ""
    assert await am.verify_session_token_async(_resign(am, payload)) is None


async def test_token_for_a_removed_user_is_rejected(auth_manager) -> None:
    """The existing username-change eviction still works."""
    am, _db = auth_manager
    await _make_user(am)
    token = await am.create_session_token_async(USERNAME)
    await am.replace_user("someone-else", "another-password")
    assert await am.verify_session_token_async(token) is None


async def test_expired_token_is_rejected(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    payload = _decode_payload(await am.create_session_token_async(USERNAME))
    payload["exp"] = 1
    assert await am.verify_session_token_async(_resign(am, payload)) is None


async def test_tampered_signature_is_rejected(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    token = await am.create_session_token_async(USERNAME)
    assert await am.verify_session_token_async(token + "x") is None


@pytest.mark.parametrize("garbage", ["", "not-a-token", "a.b.c", "....", "x." * 50])
async def test_malformed_tokens_are_rejected(auth_manager, garbage: str) -> None:
    am, _db = auth_manager
    await _make_user(am)
    assert await am.verify_session_token_async(garbage) is None


async def test_subjectless_token_is_rejected(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    payload = _decode_payload(await am.create_session_token_async(USERNAME))
    payload["sub"] = ""
    assert await am.verify_session_token_async(_resign(am, payload)) is None


async def test_fingerprint_is_none_for_unknown_user(auth_manager) -> None:
    am, _db = auth_manager
    assert await am._credential_fingerprint("nobody") is None


async def test_minting_for_an_unknown_user_yields_an_unusable_token(auth_manager) -> None:
    """No user row means no claim to add — and the result must not authenticate."""
    am, _db = auth_manager
    token = await am.create_session_token_async("ghost")
    assert "cfp" not in _decode_payload(token)
    assert await am.verify_session_token_async(token) is None


# --- F17 — honest reset-password ------------------------------------------


async def test_update_password_reports_no_change_for_unknown_username(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    assert await am.update_password("nosuchuser", "irrelevant") is False


async def test_update_password_reports_change_for_the_real_username(auth_manager) -> None:
    am, _db = auth_manager
    await _make_user(am)
    assert await am.update_password(USERNAME, "a-brand-new-password") is True
    assert await am.verify_password(USERNAME, "a-brand-new-password") is True


async def test_update_password_on_an_empty_users_table_reports_no_change(auth_manager) -> None:
    am, _db = auth_manager
    assert await am.update_password(USERNAME, "whatever") is False
