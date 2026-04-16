/**
 * OpenAPI 3.0 spec for membership-service.
 * Served at GET /docs via swagger-ui-express.
 */
export const swaggerSpec = {
  openapi: "3.0.0",
  info: {
    title: "PassGuard — Membership Service",
    version: "1.0.0",
    description:
      "Manages Priority Pass member provisioning and lifecycle. " +
      "Simulates the issuer-to-Collinson registration API. " +
      "card_token is always a tokenised reference — raw PANs are never accepted (PCI DSS v4 Req 3).",
  },
  servers: [{ url: "http://localhost:3001", description: "Local Docker" }],
  tags: [{ name: "Members", description: "Member provisioning and lifecycle" }],
  paths: {
    "/members": {
      post: {
        tags: ["Members"],
        summary: "Provision a new member",
        description:
          "Called by a card issuer (e.g. FNB, HSBC) when a cardholder activates a card with Priority Pass benefit. " +
          "Stores the tokenised card reference and assigns a tier. " +
          "Publishes a `membership.provisioned` event to Kafka.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["card_token", "issuer_id"],
                properties: {
                  card_token: {
                    type: "string",
                    minLength: 8,
                    description: "Tokenised card reference from issuer vault. Never a raw PAN.",
                    example: "tok_fnb_premier_jndifor_001",
                  },
                  issuer_id: {
                    type: "string",
                    description: "Card issuer identifier.",
                    example: "FNB-ZA",
                  },
                  tier: {
                    type: "string",
                    enum: ["standard", "prestige", "prestige_plus"],
                    default: "standard",
                    description:
                      "standard = 10 visits/yr | prestige = 20 visits/yr | prestige_plus = unlimited",
                    example: "prestige",
                  },
                },
              },
            },
          },
        },
        responses: {
          "201": {
            description: "Member provisioned successfully",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/MemberResponse" },
              },
            },
          },
          "400": { description: "Validation error — missing or invalid field" },
          "409": { description: "card_token already provisioned" },
          "500": { description: "Internal server error" },
        },
      },
    },
    "/members/{id}": {
      get: {
        tags: ["Members"],
        summary: "Get member entitlement info",
        description:
          "Returns tier, visit count, visit limit and status for a member. " +
          "card_token is never returned — not needed by callers (PCI DSS v4 Req 3).",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
            description: "Member UUID returned at provisioning time",
            example: "ffe4cace-2054-4634-a9e4-41d2401938a9",
          },
        ],
        responses: {
          "200": {
            description: "Member found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/MemberResponse" },
              },
            },
          },
          "400": { description: "Invalid UUID format" },
          "404": { description: "Member not found" },
        },
      },
    },
    "/members/{id}/status": {
      patch: {
        tags: ["Members"],
        summary: "Update member status",
        description:
          "Suspend or cancel a membership — e.g. when a card is cancelled by the issuer. " +
          "Requires actor field for audit trail (PCI DSS v4 Req 10).",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
            example: "ffe4cace-2054-4634-a9e4-41d2401938a9",
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["status", "actor"],
                properties: {
                  status: {
                    type: "string",
                    enum: ["active", "suspended", "cancelled"],
                    example: "suspended",
                  },
                  actor: {
                    type: "string",
                    description: "Who made this change — required for audit trail.",
                    example: "FNB-ZA",
                  },
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Status updated" },
          "400": { description: "Validation error" },
          "404": { description: "Member not found" },
        },
      },
    },
    "/health": {
      get: {
        tags: ["Members"],
        summary: "Health check",
        responses: {
          "200": { description: "Service is healthy" },
        },
      },
    },
  },
  components: {
    schemas: {
      MemberResponse: {
        type: "object",
        properties: {
          member_id: { type: "string", format: "uuid" },
          tier: { type: "string", enum: ["standard", "prestige", "prestige_plus"] },
          visit_count: { type: "integer" },
          visit_limit: { type: "integer", description: "-1 means unlimited" },
          status: { type: "string", enum: ["active", "suspended", "cancelled"] },
          issuer_id: { type: "string" },
          created_at: { type: "string", format: "date-time" },
          updated_at: { type: "string", format: "date-time" },
        },
      },
    },
  },
};
