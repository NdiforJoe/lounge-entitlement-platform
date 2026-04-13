# Research Report: Collinson Group — DevSecOps Interview Prep
Date: 2026-04-13

---

## Executive Summary

Collinson Group is a privately-held UK company (~£1.8B revenue FY25, 2,300 employees) best known as the operator of Priority Pass — the world's largest independent airport lounge access programme with 1,800+ lounges in 140+ markets. Their engineering infrastructure is AWS-first, with a modern cloud-native stack (TypeScript/Node.js, Python, Kubernetes, Kafka, PostgreSQL, MongoDB). The DevSecOps Engineer role is deeply embedded in their CISO function, with a mandate to shift security left across CI/CD pipelines using GitHub Actions/Bitbucket Pipelines, Terraform IaC, and the full Rapid7/CrowdStrike/Datadog security toolchain. PCI DSS v4 and OWASP Top 10 are the primary compliance drivers given the card-linked nature of their products. No major publicly disclosed security breaches have been identified. Their competitive moat — running both Priority Pass (B2C) and LoungeKey (B2B card-issuer only) from the same lounge network — is technically unique in the market.

---

## Key Findings by Angle

### 1. Tech Stack & Engineering Infrastructure

**Cloud Platform:** AWS is the primary cloud provider. Evidence from job listings, a Confluence-to-AWS migration case study (Automation Consultants), and AWS Security Hub appearing in their technology stack all confirm AWS dominance. Oracle Cloud also appears in tooling profiles, possibly for specific enterprise workloads.

**Languages & Frameworks:**
- **Primary:** TypeScript (Node.js backend + React frontend), Python
- **Secondary/Advantageous:** Java
- Full-stack JS/TS with React on the frontend is the dominant pattern

**Data & Streaming:**
- PostgreSQL (relational)
- MongoDB (document store)
- Kafka (event streaming — important given real-time lounge access entitlement at scale)
- GraphQL (API layer)

**Infrastructure & DevOps:**
- Container orchestration: Kubernetes
- IaC: Terraform, Ansible, Helm
- CI/CD: GitHub Actions, Bitbucket Pipelines (both in active use — they haven't standardised on one)
- Monitoring/Observability: Datadog, PagerDuty
- Collaboration: Atlassian suite (Confluence on AWS, likely Jira)

**Team Structure:** Technology & Data division is a distinct business unit. The DevSecOps Engineer sits within this division, acting as a bridge between engineering teams and CISO/security leadership. Their Cape Town office handles significant engineering work (the DevSecOps role is Cape Town hybrid).

**Engineering Culture Signals:**
- "Security-by-default" deployment philosophy
- Exploring AI-driven security approaches (mentioned explicitly in the JD)
- Equal opportunity focus; candidates asked to note pronouns — progressive culture signals
- Active investment in AI/ML for product personalisation (Chief Technology & Data Officer: Marco Pera)

---

### 2. Security & DevSecOps Posture

**Compliance Frameworks (confirmed from DevSecOps JD):**
- **PCI DSS v4** — mandatory given card-linked loyalty (Priority Pass is tied to credit/debit card issuers; lounge visit billing goes through card networks)
- **CIS Benchmarks** — AWS CIS benchmarks for cloud hardening
- **OWASP Top 10** — standard web application security baseline

**Security Architecture Principles:**
- AWS Well-Architected Framework
- Zero-trust principles
- Least privilege access
- Disaster recovery protocols

**Security Toolchain (from JD — tools either required or "advantageous"):**
| Tool | Category | Status in JD |
|---|---|---|
| Rapid7 Platform | Vulnerability management, DAST, SIEM | Mentioned explicitly |
| CrowdStrike | Endpoint/cloud security (EDR/XDR) | Advantageous |
| Datadog | Observability + security monitoring | Advantageous |
| SAST tools | Static analysis (specific tool not named) | Required concept |
| DAST tools | Dynamic analysis | Required concept |
| SIEM/SOC automation | Security event correlation | Required concept |

**Key DevSecOps Responsibilities:**
1. Embed automated security testing into CI/CD pipelines (GitHub Actions / Bitbucket Pipelines)
2. Act as technical liaison between engineering and CISO leadership
3. Implement AWS IAM, encryption, and network security hardening
4. Develop security posture reporting and metrics
5. Foster a security-conscious engineering culture
6. Explore AI-driven security approaches

**Known Incidents:** No major publicly disclosed data breaches or significant GDPR penalty actions found. Individual account fraud reports (FlyerTalk forums) exist but these are credential stuffing/phishing against end users, not infrastructure breaches. This suggests a reasonably mature security posture.

**GDPR Exposure:** Collinson processes data for 400M+ consumers across 154 countries. They operate under UK GDPR (post-Brexit) and EU GDPR. Priority Pass privacy policy is public; they have a formal Data Protection Addendum programme for partners (e.g., Upflex DPA is publicly visible).

---

### 3. How Priority Pass Works Technically

**The Core Model:** Priority Pass is a B2B2C programme. Collinson signs agreements with:
- Card issuers (banks, fintech companies, credit card programmes) who bundle PP membership as a card benefit
- Airport lounges/experience operators who join the network as access points

**Access Verification Flow (inferred from public evidence):**
1. Member opens Priority Pass app → QR code displayed (linked to active membership ID)
2. Lounge staff scan QR code at entry
3. Real-time API call validates entitlement (membership status, visit limits, guest allowances)
4. Visit is logged; billing settled between Collinson and the lounge operator
5. Digital wallet support (Apple Wallet, Google Wallet) — membership card can be stored offline

**Integration Architecture:**
- **Card issuer integration:** API-based; Collinson provides card issuers APIs to provision/de-provision memberships when cards are issued or cancelled
- **Lounge partner integration:** Lounges integrate a POS/scanning system; real-time validation APIs called at point of entry
- **SmartEarn APIs (Valuedynamx):** Off-the-shelf API platform for loyalty earn/redemption, connecting to 5,000+ retail partners
- **Kafka:** The presence of Kafka in their stack suggests event-driven architecture for real-time access events at scale across 1,800+ lounges globally

**Digital Products:**
- Priority Pass mobile app (iOS + Android)
- Digital membership cards (Apple/Google Wallet)
- Pre-booking capability for select lounges
- LoungeKey: Same underlying network as Priority Pass, but distributed exclusively through card issuer white-label programmes (no direct consumer sign-up)

**Scale:** 400M+ consumers, 1,800+ lounges, 140+ countries — this is a high-availability, globally distributed access control system with real-time entitlement checks.

---

### 4. Competitive Landscape

| Programme | Owner | Network Size | Model | Key Differentiator |
|---|---|---|---|---|
| **Priority Pass** | Collinson Group | 1,800+ lounges | B2C direct + B2B card issuer | Largest independent network; brand recognition |
| **LoungeKey** | Collinson Group | Same as PP | B2B card issuer only | White-label; same inventory as PP |
| **Mastercard Airport Experiences** | Collinson (licensed) | Same PP network | Card network benefit | Mastercard-branded version of PP |
| **DragonPass** | Independent (China-based) | 1,300+ lounges | B2C + B2B | Stronger non-lounge perks (transfers, spas, F&B); growing in APAC |
| **Plaza Premium Lounges** | Plaza Premium Group | Own-operated | Operator model | Owns/operates lounges directly |
| **Centurion Lounges** | American Express | ~40 owned | Premium card benefit | Ultra-premium; Amex card only |
| **Capital One Lounges** | Capital One | ~5 owned | Premium card benefit | Growing US footprint |
| **LoungeBuddy** | United Airlines | Various | B2C pay-per-use | Acquired by United; integrated into app |

**Collinson's Structural Advantage:**
Running Priority Pass (direct consumer) and LoungeKey (white-label B2B) from the same lounge inventory is a powerful structural moat. DragonPass is the only credible global independent competitor, but Priority Pass has a larger network and stronger relationships with major card issuers (Visa, Mastercard, Amex all white-label through Collinson).

**Airport Dimensions** (Collinson subsidiary): Directly owns and operates lounges — competing with Plaza Premium and Centurion at the premium tier while also feeding inventory into their own network.

---

### 5. Recent News & Business Developments (2024–2026)

**Financial Performance:**
- FY24 (ending April 2024): Revenue £1,536.4m (+34% YoY)
- FY25 (ending April 2025): Revenue £1,797.9m (+17% YoY)
- Privately held; no VC funding (family-owned)

**Key Moves:**
- **Mar 2026:** Airport Dimensions opens Blue Sky Premier International Lounge at Surabaya (Juanda International Airport) — ongoing APAC expansion
- **Aug 2025:** Valuedynamx Commerce Platform adds Apple Products to its rewards catalogue
- **Mar 2025:** Airport Dimensions acquired 45% stake in Blue Sky Group (Indonesia) — strategic APAC expansion
- **Mar 2025:** Collinson + China Ping An Insurance launched SmartDelay flight disruption benefits
- **Dec 2024:** Expanded APAC lounge network; Priority Pass reaches 770+ lounges in APAC
- **Dec 2024:** Strategic partnership with On-us (Visa incentive platform) for APAC cardholders
- **Jul 2024:** 71% increase in APAC airport lounge visits H1 2024
- **May 2024:** Singapore Airlines LoungeKey Pass expansion
- **Apr 2024:** LoungeKey Pass Storefront launched (pay-per-visit for non-members)
- **Apr 2024:** JV with Joyful Journey Group (Mainland China entry)
- **Aug 2024:** Valuedynamx + Expedia Group partnership drives 20% growth

**Strategic Themes:**
1. **APAC-first expansion** — Indonesia, China JV, Singapore Airlines, APAC lounge volume growth
2. **Own-operated lounges** — Airport Dimensions building premium Collinson-owned lounges
3. **Loyalty commerce** — Valuedynamx scaling as a distinct platform beyond travel (retail rewards, Apple products)
4. **AI/ML investment** — Chief Technology & Data Officer Marco Pera driving data/AI agenda; "smarter, more responsive platform" language
5. **Wellness** — JV with WithU Global for digital travel wellness proposition

---

### 6. Engineering Content & Public Presence

**No public engineering blog found.** Collinson does not appear to publish engineering content publicly (no Medium, no tech.collinsongroup.com, no conference talks found).

**Their public insights content** (collinsongroup.com/insights) is marketing/thought leadership — not engineering deep-dives.

**LinkedIn** is the primary signal for tech stack — engineer profiles referencing AWS, Kafka, Kubernetes, TypeScript confirm the stack.

**Job listings** (collinsongrouptalent.com) are the richest source of confirmed technical detail — the DevSecOps and DevOps JDs are excellent prep material.

**Glassdoor** — Interview questions available; suggests process includes technical assessments and culture-fit rounds.

---

## Recommendation

For the DevSecOps interview, frame your experience around these five themes that directly map to what the job description is asking for:

1. **AWS security hardening** — Speak to IAM policies, SCPs, VPC architecture, encryption at rest/in transit, and AWS Security Hub. If you have CIS Benchmark hardening experience, lead with that.

2. **Shifting security left in CI/CD** — Their pipelines run on GitHub Actions and Bitbucket Pipelines. Talk about integrating SAST (e.g., Semgrep, Snyk, Bandit) and DAST tooling into pipeline gates. Mention secret scanning and dependency scanning.

3. **PCI DSS v4** — They handle card-linked data at scale. Understand scope reduction, tokenisation, access controls, logging requirements under PCI DSS v4. This is non-negotiable for the role.

4. **Rapid7 / CrowdStrike / Datadog** — If you have hands-on experience with any of these, it's a significant differentiator. At minimum, understand what Rapid7 InsightVM/IDR does (vuln management + SIEM), and CrowdStrike Falcon's role (EDR/XDR in cloud workloads).

5. **Zero-trust and least privilege** — They explicitly cite these principles. Talk through how you'd implement zero-trust for a globally distributed access control system (relevant to their Priority Pass lounge validation use case).

**Angle to impress:** The fact that Priority Pass handles real-time lounge access entitlement at global scale (Kafka + APIs + 1,800 endpoints) means the DevSecOps engineer needs to think about securing distributed, event-driven architectures — not just static web apps. If you can speak to API security (OAuth 2.0, JWT, rate limiting, API gateway WAF rules) and Kafka security (SASL/TLS, ACLs, schema registry), you'll stand out.

---

## Open Questions

1. Is the role specifically for the Priority Pass platform team, or a central security function that services all Collinson products (PP, LoungeKey, Valuedynamx, Airport Dimensions)?
2. What is the current maturity level of their DevSecOps practice — building from scratch, or inheriting an existing programme?
3. Do they use AWS Control Tower / AWS Organizations for multi-account governance?
4. Is there a SOC 2 or ISO 27001 certification in scope for this role?
5. What's the split between "shift left" work (developer tooling, pipeline security) vs. "operations" work (SIEM tuning, incident response)?

---

## Sources

- [DevSecOps Engineer Job Listing — Collinson Talent Portal](https://www.collinsongrouptalent.com/jobs/6086147-devsecops-engineer)
- [DevOps Engineer Job Listing — Collinson Talent Portal](https://www.collinsongrouptalent.com/jobs/3071612-devops-engineer)
- [Collinson Group Tech Stack — RocketReach](https://rocketreach.co/the-collinson-group-technology-stack_b5c2a722f42e0f2f)
- [Collinson Group — Harnessing Data & Technology](https://www.collinsongroup.com/en/insights/harnessing-the-power-of-data-and-technology-to-deepen-customer-engagement)
- [Confluence to AWS Migration Case Study — Automation Consultants](https://www.automation-consultants.com/atlassian-confluence-migration-for-collinson-group/)
- [Priority Pass — Collinson Group Product Page](https://www.collinsongroup.com/en/airport-and-travel-enhancement/priority-pass)
- [Valuedynamx — Collinson Group](https://www.collinsongroup.com/en/our-companies/value-dynamx)
- [Valuedynamx + Expedia Partnership (+20% growth)](https://www.businesswire.com/news/home/20240424033567/en/Valuedynamx-Partnership-With-Expedia-Group-Drives-20-Growth)
- [Valuedynamx Commerce Platform — Apple Products Launch](https://www.businesswire.com/news/home/20250812163244/en/)
- [Collinson Group Press Releases — PR Newswire](https://www.prnewswire.com/news/collinson-group/)
- [Collinson Group FY24 Annual Report (PDF)](https://assets.ctfassets.net/da60b1e39hcn/1xjMpmz8gB7llA5DmwQ2m4/7abc3e33ee5bf4878a5ee5dd16d4262c/Annual-report-and-financial-statements-FY24.pdf)
- [Collinson Group FY25 Annual Report (PDF)](https://assets.ctfassets.net/da60b1e39hcn/Oc7ADv9cxtR6Fc2i2CMOH/50037ab0ac72ced785368ed533d481af/annual-report-and-financial-statements-fy25.pdf)
- [Dragon Pass vs Priority Pass — The Professional Traveller](https://theprofessionaltraveller.com/dragon-pass-vs-priority-pass/)
- [LoungeKey vs Priority Pass — Relo.ai](https://relo.ai/travel/priority-pass-vs-loungekey-which-is-right-for-you/)
- [Priority Pass Digital Membership Card — Priority Pass Help](https://memberhelp.prioritypass.com/en-GB/support/membership-help/where-can-i-find-my-digital-membership-card)
- [Airport Dimensions — Blue Sky Group Indonesia Investment](https://www.collinsongroup.com/en/insights)
- [Nudge Security — Priority Pass Safety Profile](https://security-profiles.nudgesecurity.com/app/prioritypass-com)
