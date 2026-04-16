# PassGuard — Threat Model

**Method:** STRIDE  
**Last updated:** 2026-04-16  
**Version:** 1.0  
**Scope:** PassGuard PCI DSS v4 lounge access entitlement platform (Docker Compose / AWS)

---

## 1. System Overview

PassGuard processes real-time lounge access requests for Priority Pass members. When a member presents a QR code at a lounge terminal, PassGuard validates their entitlement in <100ms and records the event in an append-only audit trail.

### 1.1 Components in Scope

| Component | Language | Role |
|---|---|---|
| membership-service | Node.js/TS | Manages member lifecycle; stores card tokens |
| entitlement-service | Python/FastAPI | Issues and validates QR access tokens |
| audit-service | Node.js/TS | Consumes Kafka events; detects anomalies |
| PostgreSQL | — | Stores member records, audit events |
| Redis | — | Stores one-time token nonces (60s TTL) |
| Kafka | — | Event bus between services |

### 1.2 Trust Boundaries

```
INTERNET
    │
    │ HTTPS (TLS 1.2+)
    ▼
┌───────────────────────────────────────┐
│  TRUST BOUNDARY 1: Public API Layer   │  ← ALB / rate limiter
│  (membership-service :3001)           │
│  (entitlement-service :8000)          │
└──────────────┬────────────────────────┘
               │ Internal service call (HTTP)
               │
┌──────────────▼────────────────────────┐
│  TRUST BOUNDARY 2: Data Layer         │  ← VPC isolated subnets
│  PostgreSQL  Redis  Kafka             │
└──────────────┬────────────────────────┘
               │ Kafka events
┌──────────────▼────────────────────────┐
│  TRUST BOUNDARY 3: Audit Layer        │
│  (audit-service :3002)                │
└───────────────────────────────────────┘

LOUNGE TERMINAL
    │
    │ HTTPS (presents QR code payload)
    ▼
entitlement-service POST /access/validate
```

**Crossing a trust boundary is where attacks happen.** Every crossing requires authentication, authorisation, and logging.

---

## 2. Data Flow Diagram

```
Member App          membership-service          entitlement-service
    │                       │                          │
    │── POST /members ──────▶│                          │
    │                       │── INSERT members ─────▶ (PostgreSQL)
    │                       │── PRODUCE membership.provisioned ─▶ (Kafka)
    │◀── 201 {member_id} ───│                          │
    │                       │                          │
    │── POST /access/generate ──────────────────────▶  │
    │                       │◀── GET /members/{id} ────│
    │                       │──── 200 {status, tier} ─▶│
    │                       │                          │── SETEX qr:nonce:{jti} ─▶ (Redis)
    │◀────────── 200 {token} ──────────────────────────│
    │                       │                          │
[Lounge Terminal]           │                          │
    │── POST /access/validate ─────────────────────▶   │
    │                       │                          │── GETDEL qr:nonce:{jti} ─▶ (Redis)
    │                       │                          │── PRODUCE access.granted ─▶ (Kafka)
    │◀──── 200 {access: granted} ──────────────────────│
    │
                     audit-service
                          │
               ◀── CONSUME membership.provisioned, access.granted, access.denied
                          │── INSERT access_events ─▶ (PostgreSQL)
                          │── [impossible travel check]
                          │── INSERT security_alerts (if triggered)
                          │── PRODUCE security.alerts (if triggered)
```

---

## 3. STRIDE Threat Analysis

### 3.1 membership-service

#### S — Spoofing
**Threat:** An attacker impersonates a legitimate member by guessing or brute-forcing their `member_id`.

**Mitigations:**
- member_id is UUID v4 (128-bit random) — 2¹²² possible values, brute-force infeasible
- Rate limiting: 100 req/min per IP — enumeration attack takes centuries
- `/members/{id}` returns 404 for nonexistent IDs (no timing difference between "not found" and "exists but wrong auth")

**Residual risk:** LOW. No additional mitigations required.

---

#### T — Tampering
**Threat:** Attacker modifies data in transit (e.g., changes `tier: standard` to `tier: prestige`).

**Mitigations:**
- HTTPS enforced (TLS 1.2+ at ALB; HTTP redirect to HTTPS)
- Express body parser with 10KB limit (prevents large payload injection)
- Input validation on all fields (tier enum, UUID format, card_token length)

**Residual risk:** LOW.

---

#### R — Repudiation
**Threat:** A member claims they never provisioned or their account was modified without their knowledge.

**Mitigations:**
- Append-only `member_audit_log` table: every INSERT/UPDATE operation on a member record creates an audit entry with `actor`, `old_value` (JSONB), `new_value` (JSONB), and `ip_address`
- No `UPDATE` or `DELETE` operations permitted on audit tables (compliance gate #9 verifies this statically)
- Kafka event `membership.provisioned` published for every new member — two independent records

**Residual risk:** LOW.

---

#### I — Information Disclosure
**Threat:** Card PAN (Primary Account Number) exposed through the API or logs.

**Mitigations:**
- card_token is a vault reference, never the actual PAN (PCI DSS Req 3.3.1)
- card_token explicitly excluded from all SELECT queries in `/members/{id}` GET
- Compliance gate #1 scans all source files for PAN regex patterns (Visa/MC/Amex)
- Semgrep SAST (Gate 2) scans for secrets patterns
- Gitleaks (Gate 1 + pre-commit) blocks any PAN-like string from reaching git history
- Structured logs use masked IDs: `mem_****3f8a`, never full member_id

**Residual risk:** LOW. card_token is the only sensitive field; it is never returned.

---

#### D — Denial of Service
**Threat:** Attacker floods membership-service with requests, making it unavailable to legitimate members.

**Mitigations:**
- Rate limiting: 100 req/min per IP (express-rate-limit)
- Body size limit: 10KB (prevents large payload attacks)
- PostgreSQL connection pooling prevents DB connection exhaustion
- In production: AWS WAF (managed rules) in front of ALB

**Residual risk:** MEDIUM. Rate limiting is per-IP; a distributed attack from many IPs is not mitigated at the application layer. Requires WAF + CloudFront DDoS protection (AWS Shield) in production.

---

#### E — Elevation of Privilege
**Threat:** A `standard` tier member accesses a `prestige`-only lounge.

**Mitigations:**
- Tier is stored in PostgreSQL, not the client-controlled token
- entitlement-service calls membership-service to retrieve tier at validation time — client cannot modify their own tier
- Tier checked against lounge requirements before token issued (visit_limit check)

**Residual risk:** LOW.

---

### 3.2 entitlement-service

#### S — Spoofing
**Threat:** Attacker forges a QR token without knowing the HMAC secret.

**Mitigations:**
- HMAC-SHA256 signature covers the entire payload (including member_id, lounge_id, exp, jti)
- Secret is min 32 characters, loaded from env var (never in source)
- Constant-time comparison (`hmac.compare_digest`) prevents timing oracle attacks
- In production: RS256 (asymmetric) — partners can verify with public key, no secret distribution

**Residual risk:** LOW, assuming HMAC secret is strong and rotated. The `check_jwt_algorithm` compliance check (Gate 8, check #2) prevents downgrade to HS256 with weak secrets.

---

#### T — Tampering
**Threat:** Attacker intercepts a QR code and modifies the member_id or lounge_id field to gain access as a different member or at a different lounge.

**Mitigations:**
- HMAC signature covers entire payload — any bit change invalidates the signature
- `_verify_token()` runs constant-time comparison — no partial-match oracle
- Lounge ID match check: even a valid signature for LHR-T3 cannot be used at JFK-T4

**Residual risk:** NEGLIGIBLE. Cryptographic guarantee.

---

#### R — Repudiation
**Threat:** Member claims they did not enter the lounge, disputes billing.

**Mitigations:**
- `access.granted` event published to Kafka with timestamp, member_id, lounge_id, nonce
- audit-service writes event to append-only PostgreSQL table with Kafka offset (provenance chain)
- The nonce is UUID v4 — unforgeable, unique per entry event
- Redis `GETDEL` creates a record: the nonce existed (token was legitimately generated) and was consumed (validation occurred)

**Residual risk:** LOW. Strong audit chain from token generation through validation.

---

#### I — Information Disclosure
**Threat:** Attacker learns member details from token validation error messages.

**Mitigations:**
- Error messages are generic: "Invalid token signature", "Token expired", "Token already used"
- No member_id, tier, or lounge details leaked in error responses
- Structured logs use masked member IDs (`mem_****3f8a`)

**Residual risk:** LOW.

---

#### D — Denial of Service
**Threat:** Attacker floods `/access/validate` with requests, preventing legitimate lounge entry.

**Mitigations:**
- Validation checks ordered cheapest-first: signature (local) → expiry (local) → Redis GETDEL → lounge match
- Invalid signatures are rejected in <1ms without touching Redis or the database
- Redis nonce TTL of 60s naturally limits nonce storage growth
- In production: WAF rate limiting per lounge terminal IP

**Residual risk:** MEDIUM. A coordinated attack from many IPs at high RPS could exhaust Redis connections. Mitigation: Redis cluster with connection limits + AWS WAF.

---

#### E — Elevation of Privilege
**Threat:** Attacker replays an old token or uses one token at multiple lounges simultaneously.

**Mitigations:**
- One-time nonce via Redis `GETDEL` (atomic) — prevents replay entirely
- Concurrent replay test: two simultaneous validations result in exactly one GRANTED (see `test_concurrent_replay_blocked`)
- 60-second TTL limits window for physical theft of QR code

**Residual risk:** NEGLIGIBLE. Multiple independent controls.

---

### 3.3 audit-service

#### S — Spoofing
**Threat:** Attacker publishes fake events to Kafka to inject false audit records.

**Mitigations:**
- In production: Kafka SASL/SCRAM-SHA-512 authentication — only authenticated producers can write
- Kafka ACLs: membership-service and entitlement-service can produce; audit-service can only consume
- Kafka offset stored with each audit record — gaps in offset sequence indicate missing events

**Residual risk:** LOW in production (SASL enabled). In dev (plaintext), MEDIUM — mitigated by network isolation (Docker bridge network, not exposed externally).

---

#### I — Information Disclosure
**Threat:** `GET /audit/:memberId` exposes sensitive access history to unauthorised callers.

**Mitigations:**
- In the current scaffold: memberId-based access (internal service, not public-facing)
- In production: require JWT Bearer token from the operations portal; scope check (support agents can only view their own members)

**Residual risk (current):** MEDIUM — no auth on audit endpoint in dev build. Production mitigation is documented and required before go-live.

---

## 4. Attack Trees

### 4.1 QR Code Theft Attack

**Goal:** Attacker steals a member's QR code and uses it to access a lounge.

```
Steal QR code and gain lounge access
├── Steal before member uses it
│   ├── Physical: photograph QR on phone screen
│   │   └── MITIGATED: 60-second TTL (useless after 60s)
│   └── Network: intercept HTTPS traffic
│       └── MITIGATED: TLS 1.2+ (HTTPS only)
│
└── Steal after member uses it
    └── Replay the used token
        └── MITIGATED: Redis GETDEL (nonce already consumed)
```

**Verdict:** BLOCKED by TTL + one-time nonce. Both must fail simultaneously for attack to succeed.

---

### 4.2 Replay Attack

**Goal:** Use a valid QR code more than once.

```
Replay valid token
├── Simple replay (same token, same lounge, later time)
│   └── MITIGATED: Nonce GETDEL removes nonce on first use
│
├── Concurrent replay (two requests simultaneously)
│   └── MITIGATED: GETDEL is atomic — only one caller gets nonce
│       └── Tests: test_concurrent_replay_blocked
│
└── Replay at different lounge
    └── MITIGATED: Lounge ID embedded in signed payload
        └── Lounge match check rejects mismatched lounge
```

**Verdict:** BLOCKED at multiple independent layers.

---

### 4.3 Card Cloning / Impossible Travel Fraud

**Goal:** Clone a member's card credential; use original and clone simultaneously at different lounges.

```
Impossible travel fraud
├── Detect: same member_id at two different lounges within 30 minutes
│   └── DETECTED: audit-service impossible travel check
│       └── Alert raised to security.alerts Kafka topic
│       └── Security alert stored in PostgreSQL
│
├── Respond: alert sent to SIEM / PagerDuty (security.alerts consumer)
│   └── In production: suspend member account automatically via webhook
│
└── Prevent recurrence: suspend member pending investigation
    └── PATCH /members/{id}/status → suspended
    └── Subsequent token generation: 403 Forbidden
```

**Verdict:** DETECTED within seconds. Not fully preventable (clone may succeed once), but detected and responded to faster than any manual review process.

---

## 5. Residual Risks and Acceptance

The following risks are acknowledged, accepted for the current scope, and documented with their mitigations required for production.

| Risk | Severity | Why Accepted | Production Mitigation |
|---|---|---|---|
| No auth on `/audit/:memberId` | MEDIUM | Internal service only in dev | JWT Bearer token + RBAC scope check |
| Kafka plaintext in dev | MEDIUM | Docker bridge network not exposed | SASL/SCRAM-SHA-512 + TLS in MSK |
| HMAC symmetric key (not RS256) | LOW | Single-service validation in dev | RS256 for partner terminal distribution |
| No WAF in dev | MEDIUM | Not internet-facing in dev | AWS WAF managed rules on ALB |
| Redis single-instance in dev | LOW | Dev only; 60s nonce TTL | ElastiCache cluster with replication |
| Nation-state KMS attack | NEGLIGIBLE | AWS physical security responsibility | Out of scope; accept |
| Lounge staff collusion | LOW | Physical control responsibility | Partner SLA + random audits; out of scope |

---

## 6. PCI DSS v4 Threat Modelling Requirement

PCI DSS v4 Requirement 6.3.3 mandates a targeted risk analysis for all security controls. This document serves as that analysis.

| Req | Control | Threat Addressed | Implemented In |
|---|---|---|---|
| 3.3.1 | No raw PAN storage | Information Disclosure (I) | membership-service schema |
| 3.7.4 | Key rotation | Spoofing (S) | KMS Terraform module |
| 4.2.1 | HMAC-SHA256 signing | Tampering (T) | entitlement-service |
| 6.4.1 | Security headers | Multiple | Helmet middleware |
| 6.4.2 | Rate limiting | DoS (D) | express-rate-limit |
| 8.3.9 | 60s token TTL | Spoofing / Replay | Redis SETEX + JWT exp |
| 10.2.1 | Audit logging | Repudiation (R) | audit-service + structlog |
| 10.3.2 | Append-only logs | Tampering of audit records | INSERT-only SQL schema |
| 11.5 | Intrusion detection | All threats | GuardDuty + impossible travel |

---

*This document should be reviewed whenever:*
- *A new service or endpoint is added*
- *A trust boundary changes*
- *A new vulnerability class is identified (e.g., new CVE class, new attack pattern)*
- *The deployment environment changes (dev → production)*
