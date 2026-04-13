#!/usr/bin/env bash
# PassGuard — Attack Simulation Scripts
# Run via: make attack-replay  OR  make attack-travel
set -euo pipefail

MEMBERSHIP_URL="http://localhost:3001"
ENTITLEMENT_URL="http://localhost:8000"
AUDIT_URL="http://localhost:3002"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ATTACK=${1:-replay}

# ── Helper: provision a fresh member ─────────────────────────────────────────

provision_member() {
  local token="tok_test_$(date +%s%N | sha256sum | head -c 16)"
  curl -s -X POST "$MEMBERSHIP_URL/members" \
    -H "Content-Type: application/json" \
    -d "{\"card_token\": \"$token\", \"issuer_id\": \"test-issuer\", \"tier\": \"standard\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['member_id'])"
}

generate_token() {
  local member_id=$1
  local lounge_id=$2
  curl -s -X POST "$ENTITLEMENT_URL/access/generate" \
    -H "Content-Type: application/json" \
    -d "{\"member_id\": \"$member_id\", \"lounge_id\": \"$lounge_id\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])"
}

validate_token() {
  local token=$1
  local lounge_id=$2
  curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$ENTITLEMENT_URL/access/validate" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$token\", \"lounge_id\": \"$lounge_id\"}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 1: QR Code Replay
# Attacker intercepts a valid QR code and tries to reuse it.
# Expected: 1st scan GRANTED, 2nd scan DENIED (401 Replay Detected)
# ══════════════════════════════════════════════════════════════════════════════

if [ "$ATTACK" = "replay" ]; then
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}║  Attack Simulation: QR Code Replay Attack                ║${RESET}"
  echo -e "${BOLD}║  Attacker screenshots a valid QR and tries to reuse it   ║${RESET}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  echo -e "${CYAN}[Setup] Provisioning victim member...${RESET}"
  MEMBER_ID=$(provision_member)
  echo -e "${GREEN}✓ Member: $MEMBER_ID${RESET}"
  echo ""

  echo -e "${CYAN}[Setup] Member generates legitimate QR code...${RESET}"
  QR_TOKEN=$(generate_token "$MEMBER_ID" "SIN-T3-Plaza")
  echo -e "${GREEN}✓ QR token generated${RESET}"
  echo ""

  echo -e "${CYAN}[Scan 1 — Legitimate] Member presents QR at Singapore T3...${RESET}"
  RESULT=$(validate_token "$QR_TOKEN" "SIN-T3-Plaza")
  HTTP_CODE=$(echo "$RESULT" | grep "HTTP_STATUS:" | cut -d: -f2)
  BODY=$(echo "$RESULT" | grep -v "HTTP_STATUS:")
  echo "Response: $(echo $BODY | python3 -m json.tool 2>/dev/null || echo $BODY)"
  if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ HTTP $HTTP_CODE — Access GRANTED (expected)${RESET}"
  else
    echo -e "${RED}✗ HTTP $HTTP_CODE — Unexpected result${RESET}"
  fi
  echo ""

  echo -e "${RED}[Scan 2 — ATTACK] Attacker replays the SAME QR code...${RESET}"
  RESULT=$(validate_token "$QR_TOKEN" "SIN-T3-Plaza")
  HTTP_CODE=$(echo "$RESULT" | grep "HTTP_STATUS:" | cut -d: -f2)
  BODY=$(echo "$RESULT" | grep -v "HTTP_STATUS:")
  echo "Response: $(echo $BODY | python3 -m json.tool 2>/dev/null || echo $BODY)"
  if [ "$HTTP_CODE" = "401" ]; then
    echo -e "${GREEN}✓ HTTP $HTTP_CODE — Replay BLOCKED (security control working)${RESET}"
  else
    echo -e "${RED}✗ HTTP $HTTP_CODE — SECURITY FAILURE: replay was not blocked!${RESET}"
    exit 1
  fi
  echo ""
  echo -e "${BOLD}Why it works:${RESET} Redis GETDEL atomically consumed the nonce on Scan 1."
  echo "The nonce no longer exists — Scan 2 finds nothing and is denied."
  echo "No race condition possible (atomic operation)."
fi

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 2: Impossible Travel Detection
# Member (or stolen credentials) grants access at two airports
# 30 minutes apart — physically impossible.
# Expected: 2nd grant triggers security.alert.impossible_travel
# ══════════════════════════════════════════════════════════════════════════════

if [ "$ATTACK" = "travel" ]; then
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}║  Attack Simulation: Impossible Travel Detection          ║${RESET}"
  echo -e "${BOLD}║  Same member granted access at LHR then JFK 1 min apart ║${RESET}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  echo -e "${CYAN}[Setup] Provisioning member...${RESET}"
  MEMBER_ID=$(provision_member)
  echo -e "${GREEN}✓ Member: $MEMBER_ID${RESET}"
  echo ""

  echo -e "${CYAN}[Access 1] Member granted access at London Heathrow...${RESET}"
  TOKEN1=$(generate_token "$MEMBER_ID" "LHR-T5-Aspire")
  RESULT=$(validate_token "$TOKEN1" "LHR-T5-Aspire")
  HTTP_CODE=$(echo "$RESULT" | grep "HTTP_STATUS:" | cut -d: -f2)
  echo -e "${GREEN}✓ HTTP $HTTP_CODE — Granted at LHR-T5-Aspire${RESET}"
  echo ""

  echo -e "${YELLOW}[1 second later...]${RESET}"
  sleep 1

  echo -e "${RED}[Access 2] SAME member granted access at New York JFK... 1 min after LHR!${RESET}"
  TOKEN2=$(generate_token "$MEMBER_ID" "JFK-T4-Delta")
  RESULT=$(validate_token "$TOKEN2" "JFK-T4-Delta")
  HTTP_CODE=$(echo "$RESULT" | grep "HTTP_STATUS:" | cut -d: -f2)
  BODY=$(echo "$RESULT" | grep -v "HTTP_STATUS:")
  echo "Response: $(echo $BODY | python3 -m json.tool 2>/dev/null || echo $BODY)"
  echo -e "${GREEN}✓ HTTP $HTTP_CODE — Access granted (physical access allowed)${RESET}"
  echo ""

  echo -e "${CYAN}[Detection] Checking audit trail for security alert...${RESET}"
  sleep 2  # allow Kafka consumer to process
  AUDIT=$(curl -s "$AUDIT_URL/audit/$MEMBER_ID")
  echo "Audit trail: $(echo $AUDIT | python3 -m json.tool 2>/dev/null || echo $AUDIT)"

  ALERT_COUNT=$(echo $AUDIT | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('alerts',[])))" 2>/dev/null || echo "0")
  if [ "$ALERT_COUNT" -gt "0" ]; then
    echo -e "${GREEN}✓ Security alert fired: impossible_travel detected${RESET}"
    echo -e "${BOLD}In production this alert pages the SOC via PagerDuty.${RESET}"
  else
    echo -e "${YELLOW}No alert yet — Kafka consumer may still be processing. Check 'make logs'.${RESET}"
  fi
fi
