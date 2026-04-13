/**
 * audit-service — PassGuard
 *
 * Consumes all Kafka events and writes an append-only audit log.
 * Also performs real-time impossible travel detection.
 *
 * PCI DSS v4 Requirement 10: Log and Monitor All Access to System Components
 * - All access events (granted/denied) are persisted
 * - Logs are append-only (no UPDATE/DELETE on audit tables)
 * - Retention: 7 years minimum (enforced at DB level via partitioning in prod)
 */

import express from "express";
import helmet from "helmet";
import { Pool } from "pg";
import { Kafka, Consumer, logLevel, EachMessagePayload } from "kafkajs";

const PORT = parseInt(process.env.PORT ?? "3002", 10);
const IMPOSSIBLE_TRAVEL_WINDOW_MS =
  parseInt(process.env.IMPOSSIBLE_TRAVEL_WINDOW_MINUTES ?? "30", 10) * 60 * 1000;

// ── Database ──────────────────────────────────────────────────────────────────

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function initAuditSchema(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_events (
      id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      event_type   VARCHAR(50)  NOT NULL,
      member_id    VARCHAR(255),
      lounge_id    VARCHAR(100),
      reason       VARCHAR(100),
      raw_payload  JSONB        NOT NULL,
      kafka_offset BIGINT,
      created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS security_alerts (
      id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      alert_type   VARCHAR(100) NOT NULL,
      member_id    VARCHAR(255),
      details      JSONB        NOT NULL,
      created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_access_events_member   ON access_events(member_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_access_events_type     ON access_events(event_type, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_security_alerts_member ON security_alerts(member_id, created_at DESC);
  `);
}

// ── Impossible travel detection ───────────────────────────────────────────────

/**
 * Checks if the same member was granted access at a different lounge
 * within the configured window. If so, raises a security alert.
 *
 * This is a simplified heuristic. Production would use a geolocation DB
 * to compute minimum flight time between two airports.
 */
async function checkImpossibleTravel(
  memberId: string,
  currentLoungeId: string,
  currentTime: Date
): Promise<void> {
  const windowStart = new Date(currentTime.getTime() - IMPOSSIBLE_TRAVEL_WINDOW_MS);

  const recent = await pool.query<{ lounge_id: string; created_at: Date }>(
    `SELECT lounge_id, created_at
     FROM access_events
     WHERE member_id = $1
       AND event_type = 'access.granted'
       AND lounge_id != $2
       AND created_at >= $3
     ORDER BY created_at DESC
     LIMIT 1`,
    [memberId, currentLoungeId, windowStart]
  );

  if (recent.rows.length > 0) {
    const previous = recent.rows[0];
    const minutesApart = Math.round(
      (currentTime.getTime() - new Date(previous.created_at).getTime()) / 60000
    );

    console.warn(
      `[SECURITY ALERT] Impossible travel detected: member ${memberId} ` +
        `was at ${previous.lounge_id} ${minutesApart} min ago, now at ${currentLoungeId}`
    );

    // Write security alert (append-only)
    await pool.query(
      `INSERT INTO security_alerts (alert_type, member_id, details)
       VALUES ('impossible_travel', $1, $2)`,
      [
        memberId,
        JSON.stringify({
          previous_lounge: previous.lounge_id,
          previous_time: previous.created_at,
          current_lounge: currentLoungeId,
          current_time: currentTime.toISOString(),
          minutes_apart: minutesApart,
          window_minutes: IMPOSSIBLE_TRAVEL_WINDOW_MS / 60000,
        }),
      ]
    );

    // In production: publish to security.alerts topic → SIEM / PagerDuty
    await kafkaProducer.send({
      topic: "security.alerts",
      messages: [
        {
          key: memberId,
          value: JSON.stringify({
            eventType: "security.alert.impossible_travel",
            member_id: memberId,
            previous_lounge: previous.lounge_id,
            current_lounge: currentLoungeId,
            minutes_apart: minutesApart,
            timestamp: currentTime.toISOString(),
          }),
        },
      ],
    });
  }
}

// ── Kafka ──────────────────────────────────────────────────────────────────────

const kafka = new Kafka({
  clientId: "audit-service",
  brokers: (process.env.KAFKA_BROKERS ?? "localhost:9092").split(","),
  logLevel: logLevel.WARN,
});

const consumer: Consumer = kafka.consumer({ groupId: "audit-service-group" });
const kafkaProducer = kafka.producer();

const TOPICS = ["membership.provisioned", "access.granted", "access.denied"];

async function processMessage({ topic, partition, message }: EachMessagePayload): Promise<void> {
  if (!message.value) return;

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(message.value.toString());
  } catch {
    console.error("Failed to parse Kafka message:", message.value.toString());
    return;
  }

  const eventType = (payload.eventType as string) ?? topic;
  const memberId = (payload.member_id as string) ?? undefined;
  const loungeId = (payload.lounge_id as string) ?? undefined;
  const reason = (payload.reason as string) ?? undefined;
  const now = new Date();

  // Persist to append-only audit log
  await pool.query(
    `INSERT INTO access_events
       (event_type, member_id, lounge_id, reason, raw_payload, kafka_offset)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [eventType, memberId ?? null, loungeId ?? null, reason ?? null, payload, message.offset]
  );

  // Run impossible travel check on successful grants
  if (eventType === "access.granted" && memberId && loungeId) {
    await checkImpossibleTravel(memberId, loungeId, now);
  }

  console.log(`[audit] ${eventType} | member=${memberId ?? "?"} lounge=${loungeId ?? "?"}`);
}

// ── HTTP API ──────────────────────────────────────────────────────────────────

const app = express();
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "audit-service" });
});

app.get("/audit/:memberId", async (req, res) => {
  const { memberId } = req.params;
  if (!/^[0-9a-f-]{36}$/i.test(memberId)) {
    return res.status(400).json({ error: "Invalid member ID" });
  }
  try {
    const events = await pool.query(
      `SELECT id, event_type, lounge_id, reason, created_at
       FROM access_events WHERE member_id = $1
       ORDER BY created_at DESC LIMIT 20`,
      [memberId]
    );
    const alerts = await pool.query(
      `SELECT id, alert_type, details, created_at
       FROM security_alerts WHERE member_id = $1
       ORDER BY created_at DESC LIMIT 10`,
      [memberId]
    );
    return res.json({ events: events.rows, alerts: alerts.rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ── Startup ────────────────────────────────────────────────────────────────────

async function start() {
  await initAuditSchema();
  await kafkaProducer.connect();
  await consumer.connect();
  await consumer.subscribe({ topics: TOPICS, fromBeginning: false });
  await consumer.run({ eachMessage: processMessage });

  app.listen(PORT, () => console.log(`audit-service listening on :${PORT}`));
}

process.on("SIGTERM", async () => {
  await consumer.disconnect();
  await kafkaProducer.disconnect();
  process.exit(0);
});

start().catch((err) => {
  console.error("audit-service failed to start:", err);
  process.exit(1);
});
