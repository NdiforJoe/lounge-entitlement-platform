# test_happy_path.py — End-to-end golden path
#
# This test encodes the business requirement as a runnable spec:
# "A valid, active member can generate a QR token and use it once to enter a lounge."
#
# Why test this explicitly?
# The happy path is the most important path. If it breaks, the product is down.
# Having it as a test means any refactor that breaks the flow is caught
# immediately, not at demo time.

import pytest
import pytest_asyncio


LOUNGE_ID = "LHR-T3"


@pytest.mark.asyncio
async def test_provision_member(membership_client):
    """Member can be provisioned and returned without card_token."""
    import uuid
    card_token = f"tok_{uuid.uuid4().hex[:16]}"

    resp = await membership_client.post("/members", json={
        "card_token": card_token,
        "issuer_id": "VISA_TEST",
        "tier": "standard",
    })

    assert resp.status_code == 201
    body = resp.json()

    # Verify response shape
    assert "id" in body
    assert body["tier"] == "standard"
    assert body["status"] == "active"

    # SECURITY: card_token must NEVER appear in any response
    # If this assertion fails, we have a PCI DSS Req 3 violation
    assert "card_token" not in body
    assert card_token not in resp.text


@pytest.mark.asyncio
async def test_full_access_flow(membership_client, entitlement_client, audit_client, active_member):
    """
    Complete happy path:
      1. Generate QR token for active member
      2. Validate token at lounge — expect GRANTED
      3. Query audit trail — expect event recorded
    """
    member_id = active_member

    # Step 1: Generate QR token
    gen_resp = await entitlement_client.post("/access/generate", json={
        "member_id": member_id,
        "lounge_id": LOUNGE_ID,
    })
    assert gen_resp.status_code == 200, f"Token generation failed: {gen_resp.text}"
    token_data = gen_resp.json()

    assert "token" in token_data
    assert "expires_at" in token_data
    assert token_data["ttl_seconds"] <= 60  # PCI DSS Req 8.3.9: short-lived tokens

    token = token_data["token"]

    # Step 2: Validate token
    val_resp = await entitlement_client.post("/access/validate", json={
        "token": token,
        "lounge_id": LOUNGE_ID,
    })
    assert val_resp.status_code == 200, f"Token validation failed: {val_resp.text}"
    val_body = val_resp.json()
    assert val_body.get("access") == "granted"

    # Step 3: Audit trail should record the event
    # Give Kafka consumer ~2 seconds to process the event
    import asyncio
    await asyncio.sleep(2)

    audit_resp = await audit_client.get(f"/audit/{member_id}")
    assert audit_resp.status_code == 200
    events = audit_resp.json().get("events", [])
    assert len(events) > 0, "No audit events recorded for this member"

    granted_events = [e for e in events if e["event_type"] == "access.granted"]
    assert len(granted_events) >= 1, "access.granted event not found in audit trail"


@pytest.mark.asyncio
async def test_get_member_excludes_card_token(membership_client, active_member):
    """
    PCI DSS Req 3: Retrieving member by ID must never return the card_token.
    This is a regression test — if someone adds card_token to the SELECT
    query, this test will catch it immediately.
    """
    resp = await membership_client.get(f"/members/{active_member}")
    assert resp.status_code == 200
    body = resp.json()

    assert "card_token" not in body
    # The value wouldn't start with "tok_" if it were somehow aliased
    assert not any(str(v).startswith("tok_") for v in body.values() if isinstance(v, str))


@pytest.mark.asyncio
async def test_invalid_uuid_returns_400(membership_client):
    """
    UUID format validation prevents SQL injection attempts.
    A malformed ID should be rejected before touching the database.
    """
    malicious_inputs = [
        "' OR 1=1--",
        "../../../etc/passwd",
        "not-a-uuid",
        "",
    ]
    for bad_id in malicious_inputs:
        resp = await membership_client.get(f"/members/{bad_id}")
        assert resp.status_code in (400, 404), (
            f"Expected 400/404 for input '{bad_id}', got {resp.status_code}"
        )


@pytest.mark.asyncio
async def test_duplicate_card_token_rejected(membership_client):
    """
    PCI DSS Req 3: card_token must be unique (one token = one member).
    Duplicate provisioning should be rejected with HTTP 409.
    """
    import uuid
    card_token = f"tok_{uuid.uuid4().hex[:16]}"
    payload = {"card_token": card_token, "issuer_id": "VISA_TEST", "tier": "standard"}

    r1 = await membership_client.post("/members", json=payload)
    assert r1.status_code == 201

    r2 = await membership_client.post("/members", json=payload)
    assert r2.status_code == 409, f"Duplicate card_token should be rejected, got {r2.status_code}"
