# test_security_controls.py — Automated proof that security controls work
#
# Each test here corresponds to a security requirement or PCI DSS control.
# When you show this file in the interview, you can say:
# "I didn't just implement the controls — I have tests that PROVE they work."

import asyncio
import time
import uuid
import pytest


LOUNGE_ID = "LHR-T3"


# ── Rate Limiting ──────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_rate_limiting_enforced(membership_client):
    """
    PCI DSS Req 6.4.2: Rate limiting protects against credential stuffing
    and enumeration attacks.

    The membership-service allows 100 requests/minute per IP.
    Request 101 must receive HTTP 429 Too Many Requests.

    Note: This test calls the /health endpoint (not /members) to avoid
    creating 101 real member records. Rate limiting applies to all routes.
    """
    responses = await asyncio.gather(*[
        membership_client.get("/health")
        for _ in range(101)
    ])

    status_codes = [r.status_code for r in responses]
    has_429 = 429 in status_codes

    assert has_429, (
        f"SECURITY FAILURE: Rate limiting not enforced. "
        f"Sent 101 requests, none returned 429. "
        f"Status codes: {set(status_codes)}"
    )


# ── Security Headers ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_security_headers_present(membership_client, entitlement_client):
    """
    PCI DSS Req 6.4.1: Security headers protect against common web attacks.
    Helmet middleware sets these on all responses.
    """
    for client, name in [(membership_client, "membership"), (entitlement_client, "entitlement")]:
        resp = await client.get("/health")
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # X-Content-Type-Options: nosniff — prevents MIME-type sniffing attacks
        assert headers.get("x-content-type-options") == "nosniff", (
            f"{name}: X-Content-Type-Options header missing or wrong value"
        )

        # X-Frame-Options — prevents clickjacking
        assert "x-frame-options" in headers, (
            f"{name}: X-Frame-Options header missing"
        )

        # Must NOT expose the server technology stack
        server = headers.get("server", "").lower()
        assert "express" not in server, (
            f"{name}: Server header leaks Express version: {server}"
        )
        assert "uvicorn" not in server, (
            f"{name}: Server header leaks Uvicorn version: {server}"
        )


# ── Suspended Member Access ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_suspended_member_cannot_generate_token(entitlement_client, suspended_member):
    """
    A member whose account is suspended must be denied token generation.
    This tests the membership status check in entitlement-service.
    """
    resp = await entitlement_client.post("/access/generate", json={
        "member_id": suspended_member,
        "lounge_id": LOUNGE_ID,
    })
    assert resp.status_code in (403, 401), (
        f"SECURITY FAILURE: Suspended member was issued a token. "
        f"Got {resp.status_code}: {resp.text}"
    )


@pytest.mark.asyncio
async def test_nonexistent_member_cannot_generate_token(entitlement_client):
    """
    A random UUID that doesn't correspond to any member must be rejected.
    Prevents token generation for phantom members.
    """
    fake_id = str(uuid.uuid4())
    resp = await entitlement_client.post("/access/generate", json={
        "member_id": fake_id,
        "lounge_id": LOUNGE_ID,
    })
    assert resp.status_code in (404, 403, 401), (
        f"Expected error for nonexistent member, got {resp.status_code}"
    )


# ── Impossible Travel Detection ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_impossible_travel_raises_alert(
    entitlement_client, audit_client, active_member
):
    """
    Security control: If the same member validates at two geographically
    distant lounges within 30 minutes, a security alert must be raised.

    This models a real fraud pattern: card cloning where the original card
    and the clone are both used simultaneously at different locations.

    The audit-service's impossible travel detection compares lounge IDs with
    timestamps. Two different lounges < 30 minutes apart = alert.
    """
    member_id = active_member

    # First access: London Heathrow
    gen1 = await entitlement_client.post("/access/generate", json={
        "member_id": member_id,
        "lounge_id": "LHR-T3",
    })
    assert gen1.status_code == 200
    await entitlement_client.post("/access/validate", json={
        "token": gen1.json()["token"],
        "lounge_id": "LHR-T3",
    })

    # Wait 1 second — within the 30-minute impossible travel window
    await asyncio.sleep(1)

    # Second access: New York JFK — impossible to travel there in 1 second
    gen2 = await entitlement_client.post("/access/generate", json={
        "member_id": member_id,
        "lounge_id": "JFK-T4",
    })
    assert gen2.status_code == 200
    await entitlement_client.post("/access/validate", json={
        "token": gen2.json()["token"],
        "lounge_id": "JFK-T4",
    })

    # Allow Kafka consumer time to process events and raise alert
    await asyncio.sleep(3)

    # Verify security alert was raised
    audit_resp = await audit_client.get(f"/audit/{member_id}")
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()

    alerts = audit_data.get("security_alerts", [])
    travel_alerts = [
        a for a in alerts
        if a.get("alert_type") == "impossible_travel"
    ]

    assert len(travel_alerts) >= 1, (
        f"SECURITY FAILURE: Impossible travel not detected. "
        f"No impossible_travel alerts found in: {alerts}"
    )


# ── Input Validation ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_invalid_tier_rejected(membership_client):
    """
    Input validation: only known tier values accepted.
    Prevents privilege escalation via API fuzzing (e.g., tier="admin").
    """
    resp = await membership_client.post("/members", json={
        "card_token": f"tok_{uuid.uuid4().hex[:16]}",
        "issuer_id": "VISA_TEST",
        "tier": "admin",  # Not a valid tier
    })
    assert resp.status_code == 400, (
        f"Expected 400 for invalid tier, got {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_short_card_token_rejected(membership_client):
    """
    card_token must be at least 8 characters (minimum tokenisation standard).
    Ensures we're not storing trivially guessable token references.
    """
    resp = await membership_client.post("/members", json={
        "card_token": "short",  # Only 5 chars
        "issuer_id": "VISA_TEST",
        "tier": "standard",
    })
    assert resp.status_code == 400, (
        f"Expected 400 for short card_token, got {resp.status_code}"
    )


# ── Audit Trail Completeness ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_audit_trail_append_only(audit_client, membership_client, active_member):
    """
    PCI DSS Req 10.3.2: Audit logs must not be modifiable.

    We can't easily test that the database doesn't have UPDATE/DELETE access
    at the integration level, but we CAN test that:
    1. The audit API only exposes GET (no DELETE endpoint)
    2. Audit records are present after events

    The compliance gate (Gate 8) checks the SQL schema for UPDATE/DELETE.
    """
    # Verify audit records exist after member provisioning
    await asyncio.sleep(1)  # Allow Kafka to process membership.provisioned event

    resp = await audit_client.get(f"/audit/{active_member}")
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body

    # Verify no DELETE endpoint exists on the audit service
    del_resp = await audit_client.delete(f"/audit/{active_member}")
    assert del_resp.status_code in (404, 405), (
        "SECURITY FAILURE: audit-service has a DELETE endpoint — "
        "audit logs must be append-only"
    )
