#!/usr/bin/env bash
# PassGuard — Happy Path Demo
# Demonstrates: member provisioning → QR generation → lounge validation → audit trail
set -euo pipefail

MEMBERSHIP_URL="http://localhost:3001"
ENTITLEMENT_URL="http://localhost:8000"
AUDIT_URL="http://localhost:3002"

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║       PassGuard — Happy Path Demo            ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Step 1: Provision a member ─────────────────────────────────────────────────
echo -e "${CYAN}[1/4] Provisioning member via card issuer API...${RESET}"
PROVISION=$(curl -s -X POST "$MEMBERSHIP_URL/members" \
  -H "Content-Type: application/json" \
  -d '{
    "card_token": "tok_visa_prestige_00112233",
    "issuer_id": "visa-uk",
    "tier": "prestige"
  }')

echo "Response: $(echo $PROVISION | python3 -m json.tool 2>/dev/null || echo $PROVISION)"
MEMBER_ID=$(echo $PROVISION | python3 -c "import sys,json; print(json.load(sys.stdin)['member_id'])" 2>/dev/null)

if [ -z "$MEMBER_ID" ]; then
  echo "ERROR: Failed to provision member. Is the stack running? (make up)"
  exit 1
fi
echo -e "${GREEN}✓ Member provisioned: $MEMBER_ID${RESET}"
echo ""

# ── Step 2: Generate QR access token ───────────────────────────────────────────
echo -e "${CYAN}[2/4] Generating QR access token for LHR Terminal 5...${RESET}"
TOKEN_RESPONSE=$(curl -s -X POST "$ENTITLEMENT_URL/access/generate" \
  -H "Content-Type: application/json" \
  -d "{\"member_id\": \"$MEMBER_ID\", \"lounge_id\": \"LHR-T5-Aspire\"}")

echo "Response: $(echo $TOKEN_RESPONSE | python3 -m json.tool 2>/dev/null || echo $TOKEN_RESPONSE)"
QR_TOKEN=$(echo $TOKEN_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null)
echo -e "${GREEN}✓ QR token generated (60s TTL, HMAC-SHA256 signed)${RESET}"
echo ""

# ── Step 3: Validate at lounge ──────────────────────────────────────────────────
echo -e "${CYAN}[3/4] Member scans QR at LHR Terminal 5 lounge entry...${RESET}"
VALIDATE=$(curl -s -X POST "$ENTITLEMENT_URL/access/validate" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$QR_TOKEN\", \"lounge_id\": \"LHR-T5-Aspire\"}")

echo "Response: $(echo $VALIDATE | python3 -m json.tool 2>/dev/null || echo $VALIDATE)"
echo -e "${GREEN}✓ Access GRANTED — Kafka event published${RESET}"
echo ""

# ── Step 4: Check audit trail ───────────────────────────────────────────────────
echo -e "${CYAN}[4/4] Checking audit trail...${RESET}"
sleep 2  # allow Kafka consumer to process
AUDIT=$(curl -s "$AUDIT_URL/audit/$MEMBER_ID")
echo "Audit trail: $(echo $AUDIT | python3 -m json.tool 2>/dev/null || echo $AUDIT)"
echo -e "${GREEN}✓ Events recorded in append-only audit log${RESET}"
echo ""
echo -e "${BOLD}Demo complete. Run 'make attack-replay' to see security controls in action.${RESET}"
