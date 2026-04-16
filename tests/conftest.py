# conftest.py — Shared fixtures for PassGuard integration tests
#
# Philosophy: Integration tests start real services via Docker Compose and
# fire real HTTP requests. No mocks. If the security control isn't enforced
# by the running code, the test fails.
#
# Why pytest fixtures for this:
# - `scope="session"` means Docker Compose starts ONCE for the full test run,
#   not per test. Startup is slow (~15s); we pay it once.
# - Each test gets a clean member ID via the `active_member` fixture so tests
#   don't interfere with each other's state.

import asyncio
import time
import uuid
import httpx
import pytest
import pytest_asyncio


BASE_MEMBERSHIP = "http://localhost:3001"
BASE_ENTITLEMENT = "http://localhost:8000"
BASE_AUDIT = "http://localhost:3002"

# ── Event loop ────────────────────────────────────────────────────────────────
# Single event loop shared across all async tests in the session.
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── HTTP clients ──────────────────────────────────────────────────────────────
# Async httpx clients — one per service, reused across tests.
@pytest_asyncio.fixture(scope="session")
async def membership_client():
    async with httpx.AsyncClient(base_url=BASE_MEMBERSHIP, timeout=10.0) as client:
        yield client


@pytest_asyncio.fixture(scope="session")
async def entitlement_client():
    async with httpx.AsyncClient(base_url=BASE_ENTITLEMENT, timeout=10.0) as client:
        yield client


@pytest_asyncio.fixture(scope="session")
async def audit_client():
    async with httpx.AsyncClient(base_url=BASE_AUDIT, timeout=10.0) as client:
        yield client


# ── Wait for services to be healthy ──────────────────────────────────────────
@pytest_asyncio.fixture(scope="session", autouse=True)
async def wait_for_services(membership_client, entitlement_client, audit_client):
    """
    Poll health endpoints until all services are up.
    This replaces `sleep 10` with a proper readiness check — tests start
    as soon as services are ready, not after an arbitrary sleep.
    """
    services = [
        (membership_client, "/health", "membership-service"),
        (entitlement_client, "/health", "entitlement-service"),
        (audit_client, "/health", "audit-service"),
    ]
    deadline = time.time() + 60  # 60-second startup timeout
    for client, path, name in services:
        while time.time() < deadline:
            try:
                r = await client.get(path)
                if r.status_code == 200:
                    print(f"  ✓ {name} is healthy")
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(1)
        else:
            pytest.fail(f"{name} did not become healthy within 60 seconds")


# ── Member factories ───────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def active_member(membership_client) -> str:
    """
    Provision a fresh ACTIVE member and return their member_id.
    Each test that needs a member gets its own — no shared state between tests.
    """
    card_token = f"tok_{uuid.uuid4().hex[:16]}"
    resp = await membership_client.post("/members", json={
        "card_token": card_token,
        "issuer_id": "VISA_TEST",
        "tier": "standard",
    })
    assert resp.status_code == 201, f"Failed to create member: {resp.text}"
    return resp.json()["id"]


@pytest_asyncio.fixture
async def prestige_member(membership_client) -> str:
    """A prestige-tier member (higher visit limits)."""
    card_token = f"tok_{uuid.uuid4().hex[:16]}"
    resp = await membership_client.post("/members", json={
        "card_token": card_token,
        "issuer_id": "AMEX_TEST",
        "tier": "prestige",
    })
    assert resp.status_code == 201
    return resp.json()["id"]


@pytest_asyncio.fixture
async def suspended_member(membership_client) -> str:
    """
    Provision a member then immediately suspend them.
    Used to test that suspended members cannot generate tokens.
    """
    card_token = f"tok_{uuid.uuid4().hex[:16]}"
    create_resp = await membership_client.post("/members", json={
        "card_token": card_token,
        "issuer_id": "VISA_TEST",
        "tier": "standard",
    })
    assert create_resp.status_code == 201
    member_id = create_resp.json()["id"]

    suspend_resp = await membership_client.patch(
        f"/members/{member_id}/status",
        json={"status": "suspended", "actor": "test-fixture"}
    )
    assert suspend_resp.status_code == 200
    return member_id
