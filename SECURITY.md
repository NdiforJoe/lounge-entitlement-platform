# Security Policy

## Supported Versions

PassGuard is a portfolio/demonstration project. The `main` branch is the only
supported version. Security fixes are applied to `main` directly.

| Branch | Supported |
|--------|-----------|
| `main` | Yes       |
| Any feature branch | No — merge to `main` first |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Public issue disclosure gives attackers a head start before a fix is available.
We follow responsible disclosure: you report privately, we fix, then we
coordinate public disclosure together.

### How to report

Email: **jndiforad@gmail.com**

Use the subject line: `[SECURITY] PassGuard — <brief description>`

Encrypt your report if it contains sensitive details:
```
PGP key: not yet published — plaintext email is acceptable for this project
```

### What to include

A useful report contains:
- **Type of vulnerability** (e.g. IDOR, SSRF, broken auth, secret exposure)
- **Component affected** (membership-service, entitlement-service, audit-service, CI pipeline)
- **Steps to reproduce** — specific HTTP requests, environment, preconditions
- **Impact** — what an attacker could achieve with this vulnerability
- **Suggested fix** (optional, but appreciated)

### What to expect

| Timeline | Action |
|----------|--------|
| **24 hours** | Acknowledge receipt of your report |
| **72 hours** | Initial severity assessment and triage |
| **7 days** | Fix deployed to `main` for Critical/High findings |
| **14 days** | Fix deployed for Medium findings |
| **30 days** | Public disclosure (coordinated with reporter) |

We will credit you in the commit message and release notes unless you prefer
to remain anonymous.

## Security Design Principles

PassGuard is built on the following security principles — understanding these
helps reporters identify genuine vulnerabilities vs. intended behaviour:

1. **Zero-trust entitlement** — every access request is verified independently,
   even from authenticated members
2. **Cryptographically signed tokens** — QR codes cannot be forged without the
   HMAC secret
3. **One-time nonces** — each token can only be validated once (replay is
   blocked atomically via Redis GETDEL)
4. **Short-lived tokens** — 60-second TTL limits the window for theft
5. **Append-only audit trail** — no event can be deleted or modified post-write
6. **No raw PAN storage** — only tokenised card references are stored

## Out of Scope

The following are **not** considered vulnerabilities in this project:

- Attacks requiring physical access to the lounge terminal
- Denial-of-service via resource exhaustion (Docker Compose has no production
  resource limits — this is a demo environment)
- Issues in third-party dependencies (report to the upstream project; we will
  update our dependency once they publish a fix)
- Findings from automated scanners with no demonstrated exploitability

## Compliance

This project models PCI DSS v4.0 compliance. Vulnerabilities that would cause
a PCI DSS control failure are treated as **Critical** regardless of CVSS score.

Relevant requirements:
- Req 3: Protect stored account data
- Req 6: Develop and maintain secure systems and software
- Req 10: Log and monitor all access to system components
- Req 12.10: Maintain an incident response plan

---

*Last updated: 2026-04-16*
