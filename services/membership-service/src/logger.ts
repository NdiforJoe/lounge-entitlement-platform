/**
 * Structured JSON logger — membership-service
 *
 * Why structured logging (not console.log)?
 *
 * console.log("Member abc123 granted access") is human-readable but machine-
 * hostile. A SIEM (Splunk, Datadog, CloudWatch Logs Insights) needs to:
 *   - Filter by member_id
 *   - Count events per lounge per hour
 *   - Alert on error rate spikes
 *
 * With free-text logs, that means fragile regex. With structured JSON, it's
 * a simple field filter: { member_id: "abc123", level: "error" }
 *
 * PCI DSS Req 10.3: Each audit log event must capture:
 *   - User identification (member_id, actor)
 *   - Type of event (event_type)
 *   - Date and time (timestamp — ISO 8601)
 *   - Success/failure indication (level: info/error)
 *   - Origin of event (service, trace_id)
 *
 * The `pci_req` field on each log entry makes compliance auditing a grep,
 * not a document review.
 */

import winston from "winston";

const SERVICE_NAME = "membership-service";

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL ?? "info",

  // JSON format — parsed by Fluent Bit / CloudWatch Logs Insights
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DDTHH:mm:ss.SSSZ" }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),

  defaultMeta: { service: SERVICE_NAME },

  transports: [
    // stdout only — Docker Compose / Kubernetes captures stdout
    // In production, Fluent Bit DaemonSet ships this to CloudWatch / Datadog
    new winston.transports.Console(),
  ],
});

/**
 * Log a PCI DSS security event with mandatory fields.
 *
 * Every call to this function is traceable to a specific PCI DSS requirement,
 * making the compliance audit a log query rather than a manual review.
 */
export function logSecurityEvent(params: {
  event_type: string;
  pci_req: string;
  actor?: string;
  member_id?: string;
  ip_address?: string;
  outcome: "success" | "failure" | "alert";
  detail?: Record<string, unknown>;
}) {
  // Mask member_id — never log full identifiers in searchable logs
  const masked_id = params.member_id
    ? `mem_****${params.member_id.slice(-4)}`
    : undefined;

  logger.info("security_event", {
    event_type: params.event_type,
    pci_req: params.pci_req,
    actor: params.actor,
    member_id: masked_id,
    ip_address: params.ip_address,
    outcome: params.outcome,
    ...params.detail,
  });
}
