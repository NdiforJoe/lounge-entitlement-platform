import { Router, Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { pool } from "../db/schema";
import { publishMemberProvisioned, publishMemberStatusChanged } from "../kafka/producer";

const router = Router();

const VALID_TIERS = ["standard", "prestige", "prestige_plus"] as const;
type Tier = (typeof VALID_TIERS)[number];

const VISIT_LIMITS: Record<Tier, number> = {
  standard: 10,
  prestige: 20,
  prestige_plus: -1, // unlimited
};

/**
 * POST /members
 * Provision a new member.
 *
 * Body:
 *   card_token  string  Tokenised card reference from issuer vault (never raw PAN)
 *   issuer_id   string  Card issuer identifier
 *   tier        string  standard | prestige | prestige_plus
 *
 * Security: card_token is treated as opaque — we never log, echo back, or
 * attempt to decode it. It serves only as a unique key to link access events
 * back to the issuer's cardholder record.
 */
router.post("/", async (req: Request, res: Response) => {
  const { card_token, issuer_id, tier = "standard" } = req.body ?? {};

  // Input validation
  if (!card_token || typeof card_token !== "string" || card_token.length < 8) {
    return res.status(400).json({ error: "card_token is required (min 8 chars)" });
  }
  if (!issuer_id || typeof issuer_id !== "string") {
    return res.status(400).json({ error: "issuer_id is required" });
  }
  if (!VALID_TIERS.includes(tier as Tier)) {
    return res.status(400).json({ error: `tier must be one of: ${VALID_TIERS.join(", ")}` });
  }

  const visitLimit = VISIT_LIMITS[tier as Tier];

  try {
    const result = await pool.query(
      `INSERT INTO members (id, card_token, tier, visit_limit, status, issuer_id)
       VALUES ($1, $2, $3, $4, 'active', $5)
       RETURNING id, tier, visit_limit, status, issuer_id, created_at`,
      [uuidv4(), card_token, tier, visitLimit, issuer_id]
    );

    const member = result.rows[0];

    // Write audit entry
    await pool.query(
      `INSERT INTO member_audit_log (member_id, action, actor, new_value, ip_address)
       VALUES ($1, 'member.provisioned', $2, $3, $4)`,
      [
        member.id,
        `issuer:${issuer_id}`,
        JSON.stringify({ tier, visit_limit: visitLimit, status: "active" }),
        req.ip,
      ]
    );

    // Publish to Kafka — note: card_token deliberately excluded from event
    await publishMemberProvisioned({
      memberId: member.id,
      issuerId: issuer_id,
      tier: member.tier,
      status: member.status,
      visitLimit: member.visit_limit,
      timestamp: new Date().toISOString(),
    });

    return res.status(201).json({
      member_id: member.id,
      tier: member.tier,
      visit_limit: member.visit_limit,
      status: member.status,
      created_at: member.created_at,
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes("unique")) {
      return res.status(409).json({ error: "card_token already provisioned" });
    }
    console.error("Failed to provision member:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /members/:id
 * Retrieve member entitlement info.
 * card_token is NEVER returned — not needed by callers.
 */
router.get("/:id", async (req: Request, res: Response) => {
  const { id } = req.params;

  // Basic UUID format check to prevent SQL injection surface
  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    return res.status(400).json({ error: "Invalid member ID format" });
  }

  try {
    const result = await pool.query(
      `SELECT id, tier, visit_count, visit_limit, status, issuer_id, created_at, updated_at
       FROM members WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Member not found" });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Failed to fetch member:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * PATCH /members/:id/status
 * Suspend or cancel a membership (e.g. card cancelled by issuer).
 */
router.patch("/:id/status", async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status, actor } = req.body ?? {};

  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    return res.status(400).json({ error: "Invalid member ID format" });
  }
  if (!["suspended", "cancelled", "active"].includes(status)) {
    return res.status(400).json({ error: "status must be: active | suspended | cancelled" });
  }
  if (!actor || typeof actor !== "string") {
    return res.status(400).json({ error: "actor is required for audit trail" });
  }

  try {
    const current = await pool.query(
      "SELECT id, status FROM members WHERE id = $1",
      [id]
    );
    if (current.rows.length === 0) {
      return res.status(404).json({ error: "Member not found" });
    }

    const oldStatus = current.rows[0].status;

    await pool.query(
      `UPDATE members SET status = $1, updated_at = NOW() WHERE id = $2`,
      [status, id]
    );

    await pool.query(
      `INSERT INTO member_audit_log (member_id, action, actor, old_value, new_value, ip_address)
       VALUES ($1, 'member.status_changed', $2, $3, $4, $5)`,
      [id, actor, JSON.stringify({ status: oldStatus }), JSON.stringify({ status }), req.ip]
    );

    await publishMemberStatusChanged({
      memberId: id,
      oldStatus,
      newStatus: status,
      actor,
      timestamp: new Date().toISOString(),
    });

    return res.json({ member_id: id, status });
  } catch (err) {
    console.error("Failed to update member status:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
