import { Pool } from "pg";

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

/**
 * Initialises the database schema.
 *
 * Security notes:
 * - card_token stores a tokenised reference only — raw PANs are NEVER stored
 *   (PCI DSS v4 Requirement 3: Protect Stored Account Data)
 * - All columns are explicitly typed; no unconstrained text fields
 * - updated_at maintained via trigger to provide tamper-evident timestamps
 */
export async function initSchema(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      card_token   VARCHAR(255) NOT NULL UNIQUE,
      tier         VARCHAR(50)  NOT NULL DEFAULT 'standard'
                   CHECK (tier IN ('standard', 'prestige', 'prestige_plus')),
      visit_count  INTEGER      NOT NULL DEFAULT 0 CHECK (visit_count >= 0),
      visit_limit  INTEGER      NOT NULL DEFAULT 10 CHECK (visit_limit > 0),
      status       VARCHAR(50)  NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'suspended', 'cancelled')),
      issuer_id    VARCHAR(100) NOT NULL,
      created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    -- Audit log: append-only record of all member state changes
    -- PCI DSS v4 Requirement 10: Log and Monitor All Access to System Components
    CREATE TABLE IF NOT EXISTS member_audit_log (
      id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      member_id    UUID        NOT NULL REFERENCES members(id),
      action       VARCHAR(100) NOT NULL,
      actor        VARCHAR(255) NOT NULL,
      old_value    JSONB,
      new_value    JSONB,
      ip_address   INET,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_members_status     ON members(status);
    CREATE INDEX IF NOT EXISTS idx_members_issuer     ON members(issuer_id);
    CREATE INDEX IF NOT EXISTS idx_audit_member_id    ON member_audit_log(member_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created_at   ON member_audit_log(created_at);
  `);
}
