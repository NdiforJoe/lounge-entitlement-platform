# test_replay_attack.py — QR Code Replay Attack Prevention
#
# Threat: A bad actor photographs or intercepts a member's QR code and
# attempts to use it again after the legitimate member has already scanned it.
#
# Defence: Redis GETDEL — the nonce is atomically retrieved and deleted in one
# operation. The second validation attempt finds no nonce and is rejected.
#
# Why GETDEL (not GET + DEL)?
# GET then DEL is two separate operations. If two requests arrive simultaneously:
#   Request A: GET nonce → "pending"
#   Request B: GET nonce → "pending"   (before A's DELETE runs)
#   Request A: DELETE nonce
#   Request B: DELETE nonce (already gone, but B already passed the GET check)
# → Two grants issued for one token. This is a TOCTOU (Time-of-Check Time-of-Use)
# race condition. GETDEL eliminates it: only one caller gets the nonce back.

import asyncio
import pytest


LOUNGE_ID = "LHR-T3"


@pytest.mark.asyncio
async def test_replay_attack_blocked(entitlement_client, active_member):
    """
    Core replay prevention test:
    - First validation: GRANTED (nonce consumed)
    - Second validation: REJECTED (nonce gone)
    """
    # Generate token
    gen_resp = await entitlement_client.post("/access/generate", json={
        "member_id": active_member,
        "lounge_id": LOUNGE_ID,
    })
    assert gen_resp.status_code == 200
    token = gen_resp.json()["token"]

    # First use — must succeed
    r1 = await entitlement_client.post("/access/validate", json={
        "token": token,
        "lounge_id": LOUNGE_ID,
    })
    assert r1.status_code == 200, f"First validation failed unexpectedly: {r1.text}"
    assert r1.json().get("access") == "granted"

    # Second use of SAME token — must be blocked
    r2 = await entitlement_client.post("/access/validate", json={
        "token": token,
        "lounge_id": LOUNGE_ID,
    })
    assert r2.status_code == 401, (
        f"SECURITY FAILURE: Replay attack succeeded! "
        f"Same token accepted twice. Got {r2.status_code}: {r2.text}"
    )


@pytest.mark.asyncio
async def test_concurrent_replay_blocked(entitlement_client, active_member):
    """
    Stress test for the TOCTOU race condition.
    Send two validation requests for the same token simultaneously.
    Exactly ONE must succeed; the other must be rejected.

    This test would FAIL if we used GET+DELETE instead of atomic GETDEL.
    """
    gen_resp = await entitlement_client.post("/access/generate", json={
        "member_id": active_member,
        "lounge_id": LOUNGE_ID,
    })
    assert gen_resp.status_code == 200
    token = gen_resp.json()["token"]

    # Fire both requests concurrently
    r1, r2 = await asyncio.gather(
        entitlement_client.post("/access/validate", json={"token": token, "lounge_id": LOUNGE_ID}),
        entitlement_client.post("/access/validate", json={"token": token, "lounge_id": LOUNGE_ID}),
    )

    statuses = sorted([r1.status_code, r2.status_code])

    assert statuses == [200, 401], (
        f"Expected exactly one grant and one reject. "
        f"Got statuses: {statuses}. "
        f"If both are 200, GETDEL atomicity is broken."
    )


@pytest.mark.asyncio
async def test_wrong_lounge_rejected(entitlement_client, active_member):
    """
    Token generated for lounge A cannot be used at lounge B.
    Prevents a stolen QR from being used at a different location.
    """
    gen_resp = await entitlement_client.post("/access/generate", json={
        "member_id": active_member,
        "lounge_id": "LHR-T3",
    })
    assert gen_resp.status_code == 200
    token = gen_resp.json()["token"]

    # Attempt to use at a different lounge
    val_resp = await entitlement_client.post("/access/validate", json={
        "token": token,
        "lounge_id": "JFK-T4",  # Wrong lounge
    })
    assert val_resp.status_code == 401, (
        f"SECURITY FAILURE: Token used at wrong lounge was accepted. "
        f"Got {val_resp.status_code}"
    )


@pytest.mark.asyncio
async def test_tampered_token_rejected(entitlement_client, active_member):
    """
    A token with a modified payload (e.g., changing member_id or lounge_id)
    must be rejected — the HMAC signature will not match.
    """
    gen_resp = await entitlement_client.post("/access/generate", json={
        "member_id": active_member,
        "lounge_id": LOUNGE_ID,
    })
    assert gen_resp.status_code == 200
    token = gen_resp.json()["token"]

    # Tamper with the payload: append garbage to make the signature invalid
    tampered_token = token[:-10] + "TAMPERED01"

    val_resp = await entitlement_client.post("/access/validate", json={
        "token": tampered_token,
        "lounge_id": LOUNGE_ID,
    })
    assert val_resp.status_code == 401, (
        f"SECURITY FAILURE: Tampered token was accepted. "
        f"Got {val_resp.status_code}"
    )


@pytest.mark.asyncio
async def test_expired_token_rejected(entitlement_client, active_member):
    """
    Tokens expire after 60 seconds. After expiry they must be rejected
    even if the nonce is still technically in Redis.
    (Redis TTL and JWT exp field provide defence-in-depth here.)
    """
    # Note: This test would take 61 seconds to run with a real sleep.
    # In CI we can shorten TTL via env var, or use a mock Redis client.
    # For now we test the format validation by submitting a clearly expired
    # token (manually crafted with past exp field).
    import base64, json, time, hmac, hashlib

    # Build a token with exp = 1 second ago
    import os
    secret = os.getenv("HMAC_SECRET", "change-me-in-production")

    payload = {
        "mid": active_member,
        "lid": LOUNGE_ID,
        "iat": int(time.time()) - 120,
        "exp": int(time.time()) - 60,  # expired 60 seconds ago
        "jti": "test-expired-jti",
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()

    sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    expired_token = f"{payload_b64}.{sig}"

    val_resp = await entitlement_client.post("/access/validate", json={
        "token": expired_token,
        "lounge_id": LOUNGE_ID,
    })
    assert val_resp.status_code == 401, (
        f"SECURITY FAILURE: Expired token was accepted. "
        f"Got {val_resp.status_code}"
    )
