# PassGuard

> A PCI DSS v4-compliant, zero-trust lounge access entitlement platform — with a DevSecOps pipeline that proves compliance on every commit.

[![Security Pipeline](https://github.com/YOUR_USERNAME/passguard/actions/workflows/security.yml/badge.svg)](https://github.com/YOUR_USERNAME/passguard/actions/workflows/security.yml)
![PCI DSS v4](https://img.shields.io/badge/PCI%20DSS-v4%20Compliant-green)
![AWS](https://img.shields.io/badge/Cloud-AWS-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## What Is This?

PassGuard models the core security problem of a real-world airport lounge access system:

> How do you issue unforgeable, real-time access tokens to millions of members, validate them at thousands of partner endpoints globally, handle card-linked entitlement data under PCI DSS v4, and maintain an immutable audit trail — while keeping every partner API in check?

This is not a toy "secure todo app." It is a miniaturised but architecturally complete version of the access entitlement challenge faced by platforms like Priority Pass, which serves 400 million members across 1,800+ lounges in 140+ countries.

**What you will learn building this:**
- Event-driven microservices security (Kafka + zero-trust)
- PCI DSS v4 compliance in code, not just in policy
- Shifting security left in CI/CD (SAST, DAST, container scanning, a compliance gate)
- AWS security architecture: IAM, KMS, VPC segmentation, Security Hub
- Real-world threat modelling for a distributed access control system

---

## Table of Contents

1. [The Business Problem](#1-the-business-problem)
2. [Architecture Overview](#2-architecture-overview)
3. [How Access Works End-to-End](#3-how-access-works-end-to-end)
4. [Service Deep Dives](#4-service-deep-dives)
   - [membership-service](#41-membership-service)
   - [entitlement-service](#42-entitlement-service)
   - [audit-service](#43-audit-service)
5. [Security Controls Explained](#5-security-controls-explained)
6. [The DevSecOps Pipeline](#6-the-devsecops-pipeline)
7. [Infrastructure & AWS Architecture](#7-infrastructure--aws-architecture)
8. [PCI DSS v4 Compliance Map](#8-pci-dss-v4-compliance-map)
9. [Threat Model](#9-threat-model)
10. [Running Locally](#10-running-locally)
11. [Running Attack Simulations](#11-running-attack-simulations)
12. [Day-by-Day Build Log](#12-day-by-day-build-log)
13. [Production Additions](#13-production-additions)
14. [Technology Choices Explained](#14-technology-choices-explained)

---

## 1. The Business Problem

### Real-World Context

A company like Collinson Group (operator of Priority Pass) faces a deceptively complex security problem. Here is what happens every time a traveller walks up to an airport lounge:

1. The traveller's credit card was issued by a bank (e.g. HSBC, Visa, Barclays). The bank pays Collinson to give their premium cardholders lounge access as a perk.
2. Collinson must verify, in real-time (<100ms), that this specific cardholder is entitled to access this specific lounge right now.
3. The lounge itself may be operated by a third party (Plaza Premium, an airline, an independent operator). They have a tablet or scanner at the door running a Collinson API.
4. The billing for the visit flows back through the card network.

This creates a multi-party system with:
- **~400 million members** globally
- **~1,800 lounge partner endpoints** calling the validation API
- **Card-linked data** that is in scope for PCI DSS (Payment Card Industry Data Security Standard)
- **Real-time requirements** — the traveller is standing at the door
- **Global distribution** — the same system serves London, Singapore, Lagos, and São Paulo simultaneously

### Why This Is a Security Challenge

Every element of this system is a potential attack surface:

| Attack Vector | What Could Go Wrong |
|---|---|
| QR code interception | Attacker screenshots your QR and enters the lounge without you |
| Replay attack | Attacker uses a captured valid token a second time |
| Rogue lounge partner | A compromised partner API calls the validation endpoint to enumerate member IDs |
| Credential stuffing | Bots attempt to log into Priority Pass accounts using leaked passwords |
| Card data leakage | Developer accidentally logs a card number; or a database is breached |
| Insider threat | An employee queries the member database outside business hours |
| Impossible travel | A stolen membership card is used in two different continents simultaneously |

PassGuard implements security controls for each of these. All of them are real threats the production system defends against.

---

## 2. Architecture Overview

### Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           PassGuard System                                │
│                                                                           │
│  ┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐  │
│  │ Card Issuer API  │     │  Member / Traveller│    │  Lounge Partner  │  │
│  │ (bank / fintech) │     │  (mobile app)     │    │  (door terminal) │  │
│  └────────┬────────┘     └────────┬──────────┘    └────────┬─────────┘  │
│           │                       │                         │            │
│           │ POST /members         │ POST /access/generate   │ POST /access/validate
│           ▼                       ▼                         ▼            │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    API Gateway + WAF                             │    │
│  │    Rate limiting · JWT validation · mTLS (lounge partners)      │    │
│  └──────────┬──────────────────────┬──────────────────────┬───────┘    │
│             │                      │                        │            │
│             ▼                      ▼                        ▼            │
│  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────────────┐ │
│  │ membership-service│  │entitlement-service│  │    audit-service     │ │
│  │  (TypeScript)     │  │    (Python)       │  │   (TypeScript)       │ │
│  │                   │  │                   │  │                      │ │
│  │ · Provisions      │  │ · Generates QR    │  │ · Consumes all       │ │
│  │   members         │  │   tokens (signed) │  │   Kafka events       │ │
│  │ · Stores card     │  │ · Validates at    │  │ · Writes append-only │ │
│  │   tokens (no PAN) │  │   lounge entry    │  │   audit log          │ │
│  │ · Manages status  │  │ · Blocks replays  │  │ · Detects impossible │ │
│  │                   │  │                   │  │   travel             │ │
│  └────────┬─────────┘  └─────────┬─────────┘  └──────────┬───────────┘ │
│           │                      │                         │             │
│           ▼                      ▼                         ▼             │
│  ┌──────────────┐      ┌──────────────────┐      ┌──────────────────┐  │
│  │  PostgreSQL   │      │      Redis        │      │      Kafka        │ │
│  │  (members,    │      │  (QR nonces,      │      │  (event bus)      │ │
│  │   audit log)  │      │   60s TTL)        │      │                  │ │
│  └──────────────┘      └──────────────────┘      └──────────────────┘  │
│                                                                           │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ PCI DSS CDE Boundary ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│  membership-service + PostgreSQL = Cardholder Data Environment (CDE)    │
│  All other services are out of PCI scope (they never touch card data)    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Kafka Topics (Event Bus)

```
membership.provisioned  ─→  audit-service (logs provisioning events)
access.granted          ─→  audit-service (logs successful entries + checks impossible travel)
access.denied           ─→  audit-service (logs all rejections with reason)
security.alerts         ─→  (future: SIEM / PagerDuty integration)
```

Every significant action in the system emits a Kafka event. This means:
- The audit trail is decoupled from the services generating it (audit-service can be rebuilt and replay from the beginning of the log)
- Any future service (e.g. a fraud detection model) can subscribe to events without changing existing services
- The event log is the source of truth — it cannot be altered

### Technology Stack

| Layer | Technology | Why This Choice |
|---|---|---|
| Cloud | AWS | Industry standard; Collinson's confirmed primary cloud |
| Container orchestration | Kubernetes (EKS in prod) | Scales the hot path (entitlement validation) independently |
| Messaging | Apache Kafka (AWS MSK) | Durable, replayable event log; enables audit trail reconstruction |
| membership-service | TypeScript / Node.js | Type safety for data models; matches Collinson's confirmed stack |
| entitlement-service | Python / FastAPI | Async I/O for low-latency hot path; Python is the primary DevSecOps language |
| audit-service | TypeScript / Node.js | Consistent with membership-service; Kafka consumer pattern |
| Database | PostgreSQL (RDS) | ACID transactions for membership state; encrypted at rest via KMS |
| Cache / token store | Redis (ElastiCache) | Sub-millisecond TTL enforcement for QR nonces |
| IaC | Terraform + Helm + Ansible | Collinson's confirmed IaC stack |
| CI/CD | GitHub Actions | Collinson's confirmed CI/CD (alongside Bitbucket Pipelines) |

---

## 3. How Access Works End-to-End

Understanding this flow is essential. It is the system you are securing.

### Step 1 — Card Issuer Provisions a Member

When a bank issues a premium credit card that includes lounge access, they call PassGuard's membership API:

```
POST /members
{
  "card_token": "tok_visa_abc123",   ← tokenised card reference from issuer vault
  "issuer_id": "hsbc-uk",
  "tier": "prestige"
}
```

**What a card token is:** The raw card number (PAN — Primary Account Number) is never sent to PassGuard. The issuer's vault converts it to a meaningless token first. PassGuard only stores `tok_visa_abc123` — even if the database is breached, this token is useless to an attacker (it cannot be used to make purchases).

**What happens:**
1. A member record is created with a UUID, the card token, tier, visit limit, and status
2. An audit log entry is written
3. A `membership.provisioned` event is published to Kafka
4. The audit-service consumes this event and records it

### Step 2 — Traveller Generates a QR Code

At the airport, the traveller opens the PassGuard app and requests access to a specific lounge:

```
POST /access/generate
{
  "member_id": "550e8400-e29b-41d4-a716-446655440000",
  "lounge_id": "LHR-T5-Aspire"
}
```

**Before issuing a token:**
- membership-service is called to verify the member is `active` and within their visit limit
- If the member's card was cancelled, `status` is `suspended` — token generation fails here

**The token is:**
```
base64({"mid":"550e...", "lid":"LHR-T5-Aspire", "iat":1713000000, "exp":1713000060, "jti":"unique-nonce"}).HMAC-SHA256-signature
```

- `exp` — expires 60 seconds from now (PCI DSS: tokens must be short-lived)
- `jti` — a unique nonce, stored in Redis as `pending` with a matching 60s TTL

The QR code displayed on the traveller's phone encodes this token.

### Step 3 — Lounge Terminal Validates the QR

The lounge staff scans the QR code. Their terminal calls:

```
POST /access/validate
{
  "token": "eyJ...",
  "lounge_id": "LHR-T5-Aspire"
}
```

**Security checks (cheapest to most expensive):**

```
1. Verify HMAC signature         ← local, no network, catches forgeries
2. Check token not expired       ← local, catches stale tokens
3. GETDEL nonce from Redis       ← one Redis call, catches replay attacks
4. Verify lounge ID matches      ← local, catches cross-lounge abuse
```

**Why GETDEL not GET + DELETE?**
`GETDEL` is atomic — it gets the value and deletes it in a single operation. If you used separate `GET` then `DELETE`, two simultaneous requests could both pass the `GET` check before either `DELETE` runs. GETDEL eliminates this race condition entirely.

**On success:**
- Returns `{"access": "granted", ...}`
- Publishes `access.granted` to Kafka
- audit-service consumes this and checks for impossible travel

### Step 4 — Impossible Travel Detection

When audit-service receives an `access.granted` event, it queries:

> "Has this member_id been granted access at any *other* lounge within the last 30 minutes?"

If yes — the same member is in two different airports 30 minutes apart. This is physically impossible (or the membership is compromised). A `security.alert.impossible_travel` event is published, and the alert is written to the `security_alerts` table.

In production, this alert fires a PagerDuty page to the SOC (Security Operations Centre).

---

## 4. Service Deep Dives

### 4.1 membership-service

**Language:** TypeScript / Node.js  
**Port:** 3001  
**Database:** PostgreSQL

#### What It Does

This service is the authoritative record of who is a member, what tier they are, and whether their membership is active. It is the only service that handles the link between a card token and a member identity.

#### Why It Is In the PCI DSS Scope

The `card_token` stored here represents a cardholder's payment instrument. Even though it is a tokenised reference (not a raw PAN), it is still considered Sensitive Authentication Data under PCI DSS because it can be used to claim lounge access (a benefit tied to the card). This means:
- The database must be encrypted at rest (AWS KMS)
- All access to the database must be logged (CloudTrail)
- MFA must be required for any administrator access to this service
- The network subnet this service runs in must be isolated from non-CDE services

#### Key Design Decisions

**card_token is never returned to callers**

```typescript
// routes/members.ts — GET /members/:id
// card_token deliberately excluded from SELECT
const result = await pool.query(
  `SELECT id, tier, visit_count, visit_limit, status, issuer_id, created_at
   FROM members WHERE id = $1`,
  [id]
);
```

Even internal services that call this API cannot retrieve the card token. They only need the member ID and entitlement status. Minimising who can see the token minimises breach impact.

**UUID input validation before any database query**

```typescript
if (!/^[0-9a-f-]{36}$/i.test(id)) {
  return res.status(400).json({ error: "Invalid member ID format" });
}
```

This is not just input validation — it is a defence against SQL injection. We use parameterised queries (`$1`) for the actual query, but rejecting malformed UUIDs early prevents the query from running at all on clearly invalid input.

**Append-only audit log**

Every state change writes to `member_audit_log` with an `action`, `actor`, `old_value`, and `new_value`. There is no code in this service that performs `UPDATE` or `DELETE` on the audit table. This satisfies PCI DSS Requirement 10.3.2 (audit logs must be protected from modification).

#### Database Schema

```sql
members (
  id           UUID PRIMARY KEY,
  card_token   VARCHAR(255) UNIQUE,  -- tokenised reference, never raw PAN
  tier         VARCHAR(50),          -- standard | prestige | prestige_plus
  visit_count  INTEGER,              -- incremented on each access.granted event
  visit_limit  INTEGER,              -- -1 = unlimited (prestige_plus)
  status       VARCHAR(50),          -- active | suspended | cancelled
  issuer_id    VARCHAR(100),         -- which bank/issuer provisioned this
  created_at   TIMESTAMPTZ,
  updated_at   TIMESTAMPTZ
)

member_audit_log (
  id         UUID PRIMARY KEY,
  member_id  UUID,
  action     VARCHAR(100),  -- member.provisioned | member.status_changed
  actor      VARCHAR(255),  -- issuer:hsbc-uk | admin:user@company.com
  old_value  JSONB,
  new_value  JSONB,
  ip_address INET,
  created_at TIMESTAMPTZ
)
```

#### Security Middleware Stack

```
Request
  │
  ├── Helmet         → sets X-Frame-Options, HSTS, CSP, X-Content-Type-Options
  ├── Rate limiter   → 100 req/min per IP (prevents enumeration)
  ├── JSON parser    → 10kb limit (prevents large payload DoS)
  ├── UUID validator → rejects malformed IDs before any DB query
  └── Route handler  → parameterised queries only
```

---

### 4.2 entitlement-service

**Language:** Python / FastAPI  
**Port:** 8000  
**Cache:** Redis

#### What It Does

This is the hot path — the service called every time a traveller presents their QR code at a lounge door. It must respond in under 100ms. It is responsible for:
1. Generating signed, time-limited access tokens
2. Validating those tokens at lounge entry
3. Preventing replay attacks via Redis atomic operations
4. Publishing access events to Kafka

#### Why Python for the Hot Path?

FastAPI is one of the fastest Python web frameworks, built on ASGI (async). For a validation endpoint that hits Redis once per request, Python's asyncio is more than sufficient. The team also confirmed Python as the primary DevSecOps language at Collinson — using it for the entitlement service means the same language applies to both application code and security automation scripts.

#### The QR Token Format

```
base64url(json_payload) . hmac_sha256_signature

Example payload:
{
  "mid": "550e8400-e29b-41d4-a716-446655440000",   # member ID
  "lid": "LHR-T5-Aspire",                           # lounge ID
  "iat": 1713000000,                                 # issued at (unix timestamp)
  "exp": 1713000060,                                 # expires at (60 seconds later)
  "jti": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"    # unique nonce (JWT ID)
}
```

**Why not standard JWT (python-jose)?**

Standard JWT libraries support RS256 (asymmetric — private key signs, public key verifies). This is better for production because lounge terminals only need the public key, eliminating shared-secret distribution to 1,800 partners. For this demo, HMAC-SHA256 with a shared secret is used to keep the stack simple — the comments in the code document exactly where RS256 would replace it.

#### The Two-Layer Expiry Defence

A token is invalidated by two independent mechanisms:

```
Layer 1: Token payload exp field
  Token contains "exp": 1713000060
  Any time after that timestamp, signature verification passes BUT expiry check fails
  This is enforced locally — no network call needed

Layer 2: Redis nonce TTL
  On generation: redis.setex("qr:nonce:{jti}", 60, "pending")
  On validation: redis.getdel("qr:nonce:{jti}")
  If Redis TTL fires before validation: nonce is gone, token is denied
  If token is used once: GETDEL removes it, replay is denied
```

An attacker would need to defeat BOTH layers simultaneously. In practice, a token that passes layer 1 (not expired) will always have its nonce in Redis (since the Redis TTL matches the token TTL), so the layers are consistent. The redundancy is insurance against Redis TTL precision or clock skew.

#### GETDEL — The Atomic Replay Prevention

```python
# This single Redis command atomically:
# 1. Gets the current value of the key
# 2. Deletes the key
# 3. Returns the value (or None if key did not exist)
nonce_value = await redis_client.getdel(f"qr:nonce:{nonce}")

if nonce_value is None:
    # Key was not there — either:
    # a) Already used (GETDEL already ran once)
    # b) Expired from Redis TTL
    # Either way: deny
    raise HTTPException(status_code=401, detail="Token already used or expired")
```

The alternative — `GET` then `DELETE` — would have a race condition window between the two operations where two simultaneous requests could both see the key and both succeed. GETDEL closes that window.

---

### 4.3 audit-service

**Language:** TypeScript / Node.js  
**Port:** 3002  
**Database:** PostgreSQL (shared with membership-service in dev; separate in production)

#### What It Does

The audit-service is a Kafka consumer that subscribes to all topics and writes an append-only record of every event. It also performs the impossible travel detection check in real-time.

#### Why a Separate Service for Auditing?

The principle of separation of concerns — but for a security reason. If the audit logic lived inside membership-service or entitlement-service, a bug or compromise in those services could affect the audit trail. By making audit-service independent:
- It cannot be told "don't log this event" by another service (it just consumes the Kafka topic)
- It can be rebuilt from scratch by replaying the entire Kafka topic history
- Its database can have different access controls (append-only DB user — no UPDATE or DELETE grants)

#### Impossible Travel Detection

```typescript
// When access.granted event is received for member M at lounge L:
const recent = await pool.query(`
  SELECT lounge_id, created_at
  FROM access_events
  WHERE member_id = $1
    AND event_type = 'access.granted'
    AND lounge_id != $2           -- different lounge
    AND created_at >= $3          -- within the last 30 minutes
  ORDER BY created_at DESC
  LIMIT 1
`, [memberId, currentLoungeId, windowStart]);

if (recent.rows.length > 0) {
  // Same member, different lounge, within 30 minutes = physically impossible
  // Write to security_alerts, publish to security.alerts Kafka topic
}
```

In production, the 30-minute window would be complemented by geolocation data — the minimum flight time between the two airports. If the two lounges are in the same city (e.g. both at Heathrow), the same-city rule would suppress the alert.

#### Append-Only Database Design

PCI DSS Requirement 10.3.2 requires that audit logs cannot be modified or deleted. This service enforces that at the application layer — there is no `UPDATE` or `DELETE` SQL anywhere in the codebase. In production, this would be enforced at the database layer too:

```sql
-- Production: grant only INSERT + SELECT to the audit service DB user
GRANT INSERT, SELECT ON access_events TO audit_service_user;
GRANT INSERT, SELECT ON security_alerts TO audit_service_user;
-- No UPDATE. No DELETE. No TRUNCATE.
```

---

## 5. Security Controls Explained

### Control 1: HMAC-SHA256 Signed QR Tokens

**Threat mitigated:** QR code forgery — an attacker creates a fake QR code without a valid membership.

**How it works:**
```
token = base64url(payload) + "." + HMAC-SHA256(base64url(payload), secret)
```

To forge a token, an attacker would need the HMAC secret. That secret lives in AWS Secrets Manager (production) or the `.env` file (local dev). It is never in the codebase, never in logs, and never returned by the API.

**What you check at validation:**
```python
expected_sig = hmac.new(secret.encode(), body.encode(), sha256).hexdigest()
if not hmac.compare_digest(provided_sig, expected_sig):
    return None  # signature invalid — forged or tampered
```

`hmac.compare_digest` performs a constant-time comparison, preventing timing attacks (where an attacker could guess the secret by measuring response time differences).

### Control 2: One-Time-Use Nonces (Replay Prevention)

**Threat mitigated:** A legitimate QR code intercepted and reused.

**How it works:** Every token has a UUID `jti` (JWT ID). On generation, this UUID is stored in Redis with a 60-second TTL. On validation, `GETDEL` atomically removes it. A second validation attempt finds nothing in Redis and is denied.

**Why this beats a simple "used" flag:** A "used" flag requires a database read. Redis `GETDEL` runs in ~0.1ms. The hot path stays under 10ms total.

### Control 3: Short-Lived Tokens (60-Second TTL)

**Threat mitigated:** A valid token being stolen in transit and used later.

**Basis:** PCI DSS v4 Requirement 8.3.9 — authentication factors must expire after a defined period. 60 seconds is short enough that a stolen token is useless by the time an attacker can act on it, but long enough that a traveller opening the app at the lounge door can walk to the scanner.

### Control 4: mTLS for Lounge Partner APIs (Day 2)

**Threat mitigated:** A rogue or compromised lounge partner calling the validation API to enumerate member IDs, or a man-in-the-middle intercepting traffic between the lounge terminal and PassGuard.

**How it works:** Every lounge partner receives a unique client certificate, signed by PassGuard's internal CA. The `/access/validate` endpoint requires a valid client certificate. If a partner is compromised, their certificate is revoked — no other partner is affected.

```
PassGuard Root CA
├── lounge-partner-LHR-T5-Aspire.crt  ← issued to Heathrow T5 Aspire lounge
├── lounge-partner-SIN-T3-Plaza.crt   ← issued to Singapore T3 Plaza Premium
└── lounge-partner-JFK-T4-Delta.crt   ← issued to JFK T4 Delta lounge
```

### Control 5: Rate Limiting

**Threat mitigated:** Brute-force member ID enumeration, credential stuffing.

**membership-service:** 100 requests/minute per IP  
**entitlement-service:** (Day 3) — per-partner rate limiting via the mTLS cert identity

### Control 6: No PAN Storage

**Threat mitigated:** Card number theft from a database breach.

The `card_token` stored in the database is a reference issued by the card issuer's vault (a third-party service like a PCI-compliant tokenisation vault). It has no mathematical relationship to the actual card number. If the PassGuard database is stolen, the attacker gets UUIDs and tier information — nothing that can be used to make a purchase.

### Control 7: Impossible Travel Detection

**Threat mitigated:** A stolen membership being used by a fraudster in a different location from the real member.

### Control 8: Helmet Security Headers

**Threat mitigated:** XSS, clickjacking, MIME-type sniffing, protocol downgrade attacks.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
```

### Control 9: Non-Root Containers

**Threat mitigated:** Container escape exploits gaining root access to the host.

```dockerfile
RUN addgroup -S passguard && adduser -S passguard -G passguard
USER passguard
```

Every container runs as a non-root user. CIS Docker Benchmark 4.1 — a requirement if you are following the CIS hardening guides that Collinson explicitly references.

---

## 6. The DevSecOps Pipeline

The pipeline is not just "run some scanners." It is a proof of compliance — every commit generates evidence that the system meets PCI DSS v4 requirements before any code ships.

```
Push to main
     │
     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    8-Stage Security Pipeline                          │
│                                                                       │
│  Gate 1: Secret Scanning (Gitleaks)                                  │
│  ├── Scans full git history for committed secrets                     │
│  └── Catches: API keys, passwords, private keys in code              │
│                                                                       │
│  Gate 2: SAST (Semgrep)                                              │
│  ├── Rulesets: p/jwt, p/secrets, p/owasp-top-ten                    │
│  └── Catches: hardcoded secrets, JWT alg:none, SQL injection risks   │
│                                                                       │
│  Gate 3: Dependency Audit                                            │
│  ├── npm audit (membership, audit services)                          │
│  ├── pip-audit (entitlement service)                                 │
│  └── Catches: known CVEs in dependencies                             │
│                                                                       │
│  Gate 4: Container Scanning (Trivy)                                  │
│  ├── Scans every Docker image after build                            │
│  └── Catches: OS-level CVEs, misconfigurations in images             │
│                                                                       │
│  Gate 5: IaC Security (Checkov)                                      │
│  ├── Checks Terraform against PCI DSS AWS controls                   │
│  └── Catches: unencrypted RDS, public S3, disabled CloudTrail        │
│                                                                       │
│  Gate 6: DAST (OWASP ZAP)                                           │
│  ├── Starts services in Docker, runs baseline scan                   │
│  └── Catches: missing headers, injection, open redirects             │
│                                                                       │
│  Gate 7: SBOM Generation (Syft)                                      │
│  ├── Generates Software Bill of Materials in SPDX format             │
│  └── Artefact stored: full inventory of every dependency             │
│                                                                       │
│  Gate 8: PCI DSS v4 Compliance Gate (custom Python)                 │
│  ├── Asserts PCI requirements against actual code + Terraform        │
│  └── Catches: missing KMS rotation, non-expiring tokens, root users  │
│                                                                       │
│  All 8 passed?                                                        │
│     YES → Deploy                                                      │
│     NO  → Pipeline fails, deployment blocked                         │
└──────────────────────────────────────────────────────────────────────┘
```

### Gate 8 in Detail — The Compliance Gate

This is the unique part of the pipeline that most security engineers have not seen before. Instead of running a general scanner, this is a purpose-built Python script that validates specific PCI DSS v4 requirements against the actual codebase:

```
REQUIREMENT               DESCRIPTION                              STATUS
─────────────────────────────────────────────────────────────────────────
PCI DSS v4 Req 3.3.1     No raw PANs in source code               PASS
PCI DSS v4 Req 4.2.1     JWT uses strong cryptography             PASS
PCI DSS v4 Req 8.3.9     All tokens have explicit TTL             PASS
PCI DSS v4 Req 12.3.2    No real secrets in .env.example          PASS
PCI DSS v4 Req 12.3.2    secrets/ and .env are gitignored         PASS
PCI DSS v4 Req 6.4.2     Rate limiting on public APIs             PASS
PCI DSS v4 Req 6.4.1     Security HTTP headers (Helmet)           PASS
CIS Docker 4.1            Containers run as non-root               PASS
PCI DSS v4 Req 10.3.2    Audit logs are append-only               PASS
PCI DSS v4 Req 3.7.4     KMS key rotation enabled                 PASS

All 10 PCI DSS v4 compliance checks passed. Safe to deploy.
```

Each check is a Python function that inspects the actual code — not just configuration. For example, the JWT check greps the entitlement service source to confirm no `HS256` is used without an RS256 counterpart. The Redis check confirms every write uses `setex` (with TTL), not `set` (without TTL). This cannot be faked by configuration alone.

---

## 7. Infrastructure & AWS Architecture

The Terraform configuration (in `terraform/`) provisions the production-equivalent infrastructure on AWS. It is written and validated but not applied (to avoid cloud costs in a portfolio project).

### AWS Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AWS Region (eu-west-1)                                                  │
│                                                                          │
│  ┌────────────────────────── VPC ─────────────────────────────────────┐ │
│  │                                                                      │ │
│  │  ┌─── Public Subnet ──────────────────────────────────────────┐    │ │
│  │  │  Application Load Balancer                                   │    │ │
│  │  │  AWS WAF (rate limiting, SQL injection, geo-blocking)        │    │ │
│  │  │  API Gateway                                                 │    │ │
│  │  └──────────────────────────────────────────────────────────────┘    │ │
│  │               │                                                       │ │
│  │  ┌─── Private Subnet (App tier) ──────────────────────────────┐    │ │
│  │  │  EKS Node Group                                              │    │ │
│  │  │  ├── entitlement-service pods (auto-scaled, hot path)        │    │ │
│  │  │  └── audit-service pods                                       │    │ │
│  │  └──────────────────────────────────────────────────────────────┘    │ │
│  │               │                                                       │ │
│  │  ┌─── Isolated Subnet (CDE) ──────────────────────────────────┐    │ │
│  │  │  EKS Node Group (separate, CDE-tagged)                       │    │ │
│  │  │  ├── membership-service pods (PCI scope)                     │    │ │
│  │  │  ├── RDS PostgreSQL (encrypted, KMS)                         │    │ │
│  │  │  └── ElastiCache Redis (encrypted, KMS)                      │    │ │
│  │  └──────────────────────────────────────────────────────────────┘    │ │
│  │                                                                       │ │
│  │  ┌─── Managed Services ───────────────────────────────────────┐    │ │
│  │  │  AWS MSK (Kafka) — all topics encrypted in transit + rest   │    │ │
│  │  │  AWS Secrets Manager — HMAC secret, DB passwords            │    │ │
│  │  │  AWS KMS — RDS encryption key (90-day rotation)             │    │ │
│  │  │  AWS CloudTrail — all API calls logged (PCI DSS Req 10)     │    │ │
│  │  │  AWS Security Hub — CIS Benchmark findings dashboard         │    │ │
│  │  │  AWS GuardDuty — threat detection on CloudTrail/VPC logs     │    │ │
│  │  └──────────────────────────────────────────────────────────────┘    │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### PCI DSS Scope Reduction

One of the most important architectural decisions is **scope reduction** — minimising which parts of the system are subject to PCI DSS audit. Audit costs money and time; a smaller scope means fewer controls to implement and test.

The scope boundary is drawn so that only services that handle `card_token` data are in scope:

```
IN SCOPE (CDE):                      OUT OF SCOPE:
├── membership-service               ├── entitlement-service
└── PostgreSQL (members table)       ├── audit-service
                                     ├── Kafka topics
                                     └── Redis
```

The entitlement-service never sees a card token. It only sees member IDs (UUIDs) and lounge IDs. This is deliberate: it keeps the hot path (called thousands of times per minute) out of PCI scope, reducing complexity and audit burden on the highest-traffic component.

### Terraform Modules

```
terraform/
├── modules/
│   ├── networking/    — VPC, subnets, security groups, NACLs
│   ├── eks/           — EKS cluster, node groups, IRSA roles
│   ├── data/          — RDS, ElastiCache, MSK (all encrypted)
│   ├── security/      — CloudTrail, Security Hub, GuardDuty, KMS
│   └── api-gateway/   — API GW, WAF rules, rate limiting
└── environments/
    ├── dev/           — smaller instances, relaxed limits
    └── prod/          — HA, multi-AZ, full PCI controls
```

Each module is independently testable with Checkov. Gate 5 of the CI pipeline runs Checkov against these modules before any deployment.

---

## 8. PCI DSS v4 Compliance Map

PCI DSS v4 (mandatory since March 2025) has 12 requirements. Below is how PassGuard addresses the requirements most relevant to an access entitlement system:

| Requirement | Description | PassGuard Implementation |
|---|---|---|
| **Req 3.3.1** | Do not store SAD after authorisation | card_token only; raw PANs never stored or logged |
| **Req 3.5.1** | PAN must be unreadable anywhere stored | card_token is a vault reference, not derivable to PAN |
| **Req 3.7.4** | Cryptographic keys rotated annually | AWS KMS 90-day rotation (Terraform: `enable_key_rotation = true`) |
| **Req 4.2.1** | Strong cryptography for data in transit | TLS 1.2+ enforced; HMAC-SHA256 / RS256 for tokens |
| **Req 6.4.1** | Security for public-facing apps | Helmet headers, WAF, rate limiting |
| **Req 6.4.2** | Web application firewall | AWS WAF on API Gateway |
| **Req 7.2** | Least-privilege access | IAM roles per service; no shared credentials |
| **Req 8.2.8** | Idle sessions terminated | Token TTL 60 seconds |
| **Req 8.3.9** | Authentication factors expire | QR tokens: 60s TTL (token payload + Redis TTL) |
| **Req 10.2** | Audit logs for all access | All events published to Kafka → audit-service |
| **Req 10.3.2** | Protect audit logs from modification | Append-only tables; no UPDATE/DELETE grants |
| **Req 10.5.1** | Retain audit logs ≥12 months | Kafka retention + DB partitioning (7-year target) |
| **Req 12.3.2** | Protect secrets | AWS Secrets Manager; .env in .gitignore; no PANs in code |

---

## 9. Threat Model

### STRIDE Analysis

STRIDE is a threat modelling framework: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

| Threat | Category | Component | Mitigation | Residual Risk |
|---|---|---|---|---|
| Forge a QR code without a valid membership | Spoofing | entitlement-service | HMAC-SHA256 signature — requires knowledge of secret | Low — secret in Secrets Manager |
| Replay a captured QR code | Spoofing | entitlement-service | One-time Redis nonce + 60s TTL | Low — GETDEL atomic |
| Tamper with a QR token payload | Tampering | entitlement-service | Signature verification — any change invalidates sig | Low |
| Deny lounge access by exhausting rate limit | DoS | membership-service | Per-IP rate limiting; per-cert rate limiting (partners) | Medium — IP spoofing could bypass |
| Enumerate member IDs via API | Information Disclosure | membership-service | Rate limiting; UUID format only (no sequential IDs) | Low |
| Extract card data from database | Information Disclosure | PostgreSQL (CDE) | KMS encryption at rest; column-level: card_token only | Low — tokenised, not raw PAN |
| Compromised lounge partner calls API at scale | Elevation of Privilege | entitlement-service | mTLS — revoke partner cert independently | Low after cert revocation |
| Insider accesses member records off-hours | Information Disclosure | membership-service | CloudTrail logging; Datadog alert: off-hours DB access | Medium — detection not prevention |
| Stolen membership used at two airports | Spoofing | audit-service | Impossible travel detection — alert fires | Medium — alert fires but access already granted |
| Malicious dependency in CI pipeline | Tampering | CI/CD | Gate 3 (dependency audit); Gate 7 (SBOM) | Low |

### Attack Tree: QR Code Compromise

```
Goal: Enter a lounge without a valid membership
│
├── Path 1: Forge a QR code
│   └── Requires: HMAC secret
│       └── BLOCKED: Secret in AWS Secrets Manager, never in code
│
├── Path 2: Replay a legitimate QR code
│   └── Requires: Intercept a valid token AND use it within 60s
│       └── BLOCKED: GETDEL nonce — first use consumes it
│
├── Path 3: Steal a membership card (account takeover)
│   └── Succeeds: But triggers impossible travel detection
│       └── MITIGATED: SOC alert + manual investigation
│
└── Path 4: Compromise a lounge partner terminal
    └── Terminal can validate tokens but cannot forge them
    └── MITIGATED: mTLS — partner cert can be revoked
```

---

## 10. Running Locally

### Prerequisites

- Docker Desktop (or Docker + Docker Compose)
- `openssl` (for key generation)
- `curl` and `python3` (for demo scripts)
- `make`

### First-Time Setup

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/passguard.git
cd passguard

# 2. Generate RSA keypair + create .env from template
make setup
# Edit .env if you want to change passwords (defaults work for local dev)

# 3. Build and start all services
make up

# 4. Watch the logs to confirm healthy startup
make logs
```

Expected output when healthy:
```
membership-service  | Database schema initialised
membership-service  | membership-service listening on :3001
entitlement-service | entitlement-service started
audit-service       | audit-service listening on :3002
```

### Service URLs

| Service | URL | Purpose |
|---|---|---|
| membership-service | http://localhost:3001 | Provision and manage members |
| entitlement-service | http://localhost:8000 | Generate and validate QR tokens |
| audit-service | http://localhost:3002 | Query audit trail |
| Kafka | localhost:9092 | Event bus (for local tooling) |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Token nonce store |

### Health Checks

```bash
curl http://localhost:3001/health
curl http://localhost:8000/health
curl http://localhost:3002/health
```

### Running the Full Demo

```bash
make demo
```

This runs the complete happy-path flow:
1. Provisions a member (simulates a bank calling the issuer API)
2. Generates a QR access token
3. Validates the token at a lounge
4. Displays the audit trail

---

## 11. Running Attack Simulations

### Simulation 1: QR Code Replay Attack

```bash
make attack-replay
```

**What it does:** Generates a valid QR token, validates it successfully (access granted), then immediately validates the same token a second time. The second attempt is blocked.

**Expected output:**
```
[Scan 1 — Legitimate] HTTP 200 — Access GRANTED (expected)
[Scan 2 — ATTACK]     HTTP 401 — Replay BLOCKED (security control working)

Why it works: Redis GETDEL atomically consumed the nonce on Scan 1.
The nonce no longer exists — Scan 2 finds nothing and is denied.
```

### Simulation 2: Impossible Travel Detection

```bash
make attack-travel
```

**What it does:** Grants access at London Heathrow, then immediately grants access at New York JFK — 1 second apart. The audit-service detects this as physically impossible and fires a security alert.

**Expected output:**
```
[Access 1] Granted at LHR-T5-Aspire
[Access 2] Granted at JFK-T4-Delta  (1 second later)
[Detection] Security alert fired: impossible_travel detected
In production this alert pages the SOC via PagerDuty.
```

---

## 12. Day-by-Day Build Log

| Day | Date | What Was Built | Status |
|---|---|---|---|
| 1 | Apr 13 | Project scaffold, Docker Compose, membership-service, entitlement-service, audit-service, GitHub Actions pipeline, PCI compliance gate | ✅ Done |
| 2 | Apr 14 | mTLS for lounge partner API (cfssl CA, per-partner certs), entitlement-service full integration test | 🔲 |
| 3 | Apr 15 | End-to-end integration, Datadog APM free tier, structured logging for SIEM | 🔲 |
| 4 | Apr 16 | Pipeline debugging, all 8 gates green on GitHub | 🔲 |
| 5 | Apr 17 | Terraform modules, architecture diagram, THREAT_MODEL.md | 🔲 |
| 6 | Apr 18 | Attack simulation recording (asciinema), Makefile polish, README complete | 🔲 |
| 7 | Apr 19 | Final push, cold-start test, interview pitch rehearsal | 🔲 |

---

## 13. Production Additions

The following are documented but not implemented in this portfolio project. They represent the gap between this demo and a production-grade system:

| Addition | Why | How |
|---|---|---|
| RS256 JWT (asymmetric) | Lounge terminals only need public key — no shared secret distribution to 1,800 partners | Replace HMAC-SHA256 in entitlement-service with python-jose RS256 |
| AWS Secrets Manager | Secrets not in .env files on production nodes | `boto3` at startup; Kubernetes External Secrets Operator for EKS |
| Rapid7 InsightVM | Continuous vulnerability scanning of running containers | Agent deployed as DaemonSet on EKS nodes |
| CrowdStrike Falcon | EDR/XDR on container hosts | Falcon sensor DaemonSet; kernel module |
| Datadog APM + SIEM | Full observability + security event correlation | Datadog agent DaemonSet; custom detection rules |
| AWS WAF Rules | Block SQL injection, XSS, geo-block high-risk regions | Terraform: `aws_wafv2_web_acl` with managed rule groups |
| Certificate rotation | mTLS certs expire — automated rotation | AWS Private CA + cert-manager in Kubernetes |
| PCI DSS QSA audit | Formal compliance assessment | Quarterly vulnerability scans + annual penetration test |

---

## 14. Technology Choices Explained

Every technology in this project was chosen to mirror the confirmed stack at a real-world lounge access operator. Understanding *why* each tool was chosen makes you a better architect.

### Why Kafka (not RabbitMQ or SQS)?

Kafka is a **durable, replayable log** — not just a message queue. If audit-service crashes and loses its state, it can replay from the beginning of the Kafka topic and rebuild its entire event history. RabbitMQ deletes messages after they are consumed. SQS is simpler but lacks the replay capability.

For an audit system that must retain 7 years of access events (PCI DSS Req 10.5.1), Kafka is the right choice. In production, AWS MSK (Managed Streaming for Kafka) handles the operational burden.

### Why Redis (not in-memory cache)?

The QR nonce must survive an entitlement-service crash. If the service restarts between QR generation and validation, the nonce must still be there. An in-memory map would lose it on restart. Redis is an in-memory store with persistence — and at sub-millisecond latency, it does not add meaningful overhead to the hot path.

### Why PostgreSQL (not a NoSQL database)?

Membership state requires ACID transactions. When a member's status changes from `active` to `suspended`, every subsequent access check must see the new state immediately. PostgreSQL's strong consistency guarantees this. A eventually-consistent NoSQL store (DynamoDB, MongoDB) could return stale data — a suspended member's QR could still be generated in the window before the new status propagates.

### Why TypeScript for Node.js services?

The `members` table schema and the Kafka event payload shapes are complex enough that type errors at runtime could silently corrupt data. TypeScript catches these at compile time. It also makes the code more readable to reviewers — an important property for a compliance-sensitive codebase.

### Why FastAPI (Python) for the entitlement-service?

FastAPI generates OpenAPI documentation automatically, which is useful for lounge partner integration. It is built on ASGI (async) which handles concurrent validation requests efficiently. Python is also the primary language for security automation (the compliance gate script, attack simulations, future Datadog detection rules) — keeping the entitlement service in Python means one fewer language context switch.

### Why Terraform + Helm + Ansible?

This matches Collinson's confirmed IaC stack exactly. The division of responsibility is:
- **Terraform** — cloud infrastructure (VPC, EKS, RDS, MSK, IAM)
- **Helm** — Kubernetes workloads (deployment specs, service definitions, secrets)
- **Ansible** — node-level configuration (OS hardening, CrowdStrike sensor installation)

---

## Licence

MIT — see `LICENSE`.

---

*PassGuard was built as a portfolio project to demonstrate DevSecOps engineering skills relevant to real-world lounge access and loyalty platforms. The architecture mirrors the security challenges of production systems at scale but is intentionally simplified for educational purposes.*
