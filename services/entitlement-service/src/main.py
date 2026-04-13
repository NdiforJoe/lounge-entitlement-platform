"""
entitlement-service — PassGuard

The hot path: generates short-lived, signed QR access tokens and validates
them at lounge entry. This is the security centrepiece of PassGuard.

Security controls implemented here:
  1. HMAC-SHA256 signed JWT tokens (RS256 in production)
  2. 60-second TTL enforced in Redis (PCI DSS: short-lived tokens)
  3. One-time-use: token marked 'used' on first validation (replay prevention)
  4. Member status check before issuing any token (suspended members denied)
  5. Kafka audit trail on every grant and denial
"""

import hashlib
import hmac
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

import httpx
import redis.asyncio as aioredis
from aiokafka import AIOKafkaProducer
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ── Config ────────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379/0"
    kafka_brokers: str = "localhost:9092"
    membership_service_url: str = "http://localhost:3001"
    hmac_secret: str = Field(..., min_length=32)
    qr_token_ttl_seconds: int = 60

    class Config:
        env_file = ".env"

settings = Settings()


# ── Globals ───────────────────────────────────────────────────────────────────

redis_client: aioredis.Redis | None = None
kafka_producer: AIOKafkaProducer | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global redis_client, kafka_producer

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    kafka_producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_brokers.split(","),
        value_serializer=lambda v: json.dumps(v).encode(),
        key_serializer=lambda k: k.encode() if k else None,
    )
    await kafka_producer.start()
    print("entitlement-service started")
    yield

    await kafka_producer.stop()
    await redis_client.aclose()


app = FastAPI(title="PassGuard Entitlement Service", lifespan=lifespan)


# ── Models ────────────────────────────────────────────────────────────────────

class GenerateTokenRequest(BaseModel):
    member_id: str = Field(..., min_length=36, max_length=36)
    lounge_id: str = Field(..., min_length=2, max_length=50)

class ValidateTokenRequest(BaseModel):
    token: str = Field(..., min_length=10)
    lounge_id: str = Field(..., min_length=2, max_length=50)


# ── Token helpers ─────────────────────────────────────────────────────────────

def _sign_token(payload: dict) -> str:
    """
    HMAC-SHA256 sign the payload.
    Format: base64url(payload).HMAC(base64url(payload), secret)

    In production this would be RS256 JWT so the lounge terminal can verify
    with only the public key — no secret distribution to 1,800 partners.
    """
    import base64
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(
        settings.hmac_secret.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{body}.{sig}"


def _verify_token(token: str) -> dict | None:
    """Verify HMAC signature and return payload, or None if invalid."""
    import base64
    parts = token.split(".")
    if len(parts) != 2:
        return None
    body, provided_sig = parts
    expected_sig = hmac.new(
        settings.hmac_secret.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    # Constant-time comparison prevents timing attacks
    if not hmac.compare_digest(provided_sig, expected_sig):
        return None
    try:
        padded = body + "=" * (4 - len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


async def _publish_event(topic: str, key: str, event: dict) -> None:
    if kafka_producer:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        await kafka_producer.send_and_wait(topic, value=event, key=key)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "entitlement-service", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/access/generate")
async def generate_token(body: GenerateTokenRequest, request: Request):
    """
    Generate a short-lived, HMAC-signed access token (QR code payload).

    Steps:
    1. Verify member exists and is active via membership-service
    2. Check visit limit not exceeded
    3. Sign a token with 60s TTL + unique nonce (prevents replay)
    4. Store nonce in Redis with TTL (second layer of expiry enforcement)
    """
    # Step 1: Verify member status
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{settings.membership_service_url}/members/{body.member_id}",
                timeout=3.0,
            )
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Membership service unavailable")

    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="Member not found")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Membership service error")

    member = resp.json()

    # Step 2: Deny suspended/cancelled members immediately
    if member["status"] != "active":
        await _publish_event("access.denied", body.member_id, {
            "eventType": "access.denied",
            "reason": "member_not_active",
            "member_id": body.member_id,
            "lounge_id": body.lounge_id,
            "member_status": member["status"],
        })
        raise HTTPException(status_code=403, detail="Membership is not active")

    # Step 3: Check visit limit (-1 = unlimited)
    if member["visit_limit"] != -1 and member["visit_count"] >= member["visit_limit"]:
        await _publish_event("access.denied", body.member_id, {
            "eventType": "access.denied",
            "reason": "visit_limit_exceeded",
            "member_id": body.member_id,
            "lounge_id": body.lounge_id,
        })
        raise HTTPException(status_code=403, detail="Visit limit exceeded")

    # Step 4: Build and sign token
    nonce = str(uuid.uuid4())
    issued_at = int(time.time())
    expires_at = issued_at + settings.qr_token_ttl_seconds

    payload = {
        "mid": body.member_id,
        "lid": body.lounge_id,
        "iat": issued_at,
        "exp": expires_at,
        "jti": nonce,          # JWT ID — unique per token, enforces one-time-use
    }
    token = _sign_token(payload)

    # Step 5: Store nonce in Redis — TTL enforced at two levels (payload exp + Redis TTL)
    # PCI DSS v4 Req 8.3: Secure Individual Non-Consumer Authentication Factors
    await redis_client.setex(
        f"qr:nonce:{nonce}",
        settings.qr_token_ttl_seconds,
        "pending",
    )

    return {
        "token": token,
        "expires_at": expires_at,
        "ttl_seconds": settings.qr_token_ttl_seconds,
        "lounge_id": body.lounge_id,
    }


@app.post("/access/validate")
async def validate_token(body: ValidateTokenRequest, request: Request):
    """
    Validate an access token at lounge entry.

    This is the HOT PATH — called by lounge terminals at the door.
    Must complete in <100ms.

    Security checks (in order of cost, cheapest first):
    1. Signature verification (HMAC, local — no network)
    2. Token expiry (local)
    3. Redis nonce check (single Redis call — prevents replay)
    4. Lounge ID match (local)
    """
    now = int(time.time())

    # Check 1: Signature
    payload = _verify_token(body.token)
    if payload is None:
        await _publish_event("access.denied", "unknown", {
            "eventType": "access.denied",
            "reason": "invalid_signature",
            "lounge_id": body.lounge_id,
            "ip": request.client.host if request.client else None,
        })
        raise HTTPException(status_code=401, detail="Invalid token signature")

    member_id = payload.get("mid", "")
    token_lounge = payload.get("lid", "")
    expires_at = payload.get("exp", 0)
    nonce = payload.get("jti", "")

    # Check 2: Expiry
    if now > expires_at:
        await _publish_event("access.denied", member_id, {
            "eventType": "access.denied",
            "reason": "token_expired",
            "member_id": member_id,
            "lounge_id": body.lounge_id,
            "expired_at": expires_at,
        })
        raise HTTPException(status_code=401, detail="Token expired")

    # Check 3: One-time-use nonce (replay prevention)
    # GETDEL atomically gets the value and deletes it — prevents TOCTOU race
    nonce_value = await redis_client.getdel(f"qr:nonce:{nonce}")
    if nonce_value is None:
        # Nonce not found = already used OR expired from Redis
        await _publish_event("access.denied", member_id, {
            "eventType": "access.denied",
            "reason": "token_replayed_or_expired",
            "member_id": member_id,
            "lounge_id": body.lounge_id,
            "nonce": nonce,
        })
        raise HTTPException(status_code=401, detail="Token already used or expired (replay detected)")

    # Check 4: Lounge ID match — token must be used at the lounge it was generated for
    if token_lounge != body.lounge_id:
        # Put the nonce back — this is a legit token, just wrong lounge
        await redis_client.setex(f"qr:nonce:{nonce}", max(0, expires_at - now), "pending")
        await _publish_event("access.denied", member_id, {
            "eventType": "access.denied",
            "reason": "lounge_mismatch",
            "member_id": member_id,
            "expected_lounge": token_lounge,
            "presented_at_lounge": body.lounge_id,
        })
        raise HTTPException(status_code=403, detail="Token not valid for this lounge")

    # All checks passed — grant access
    await _publish_event("access.granted", member_id, {
        "eventType": "access.granted",
        "member_id": member_id,
        "lounge_id": body.lounge_id,
        "nonce": nonce,
    })

    return {
        "access": "granted",
        "member_id": member_id,
        "lounge_id": body.lounge_id,
        "granted_at": datetime.now(timezone.utc).isoformat(),
    }
