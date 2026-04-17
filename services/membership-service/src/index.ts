// Datadog APM — must be imported before any other module so it can instrument
// Express, pg, and kafkajs automatically via monkey-patching.
// This gives distributed traces across membership → entitlement → audit.
import tracer from "dd-trace";
tracer.init({
  service: "membership-service",
  env: process.env.NODE_ENV ?? "development",
  version: "1.0.0",
  logInjection: true,   // Adds trace_id to Winston logs — correlates logs + traces in Datadog
});

import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import swaggerUi from "swagger-ui-express";
import { initSchema } from "./db/schema";
import { disconnectProducer } from "./kafka/producer";
import membersRouter from "./routes/members";
import { logger } from "./logger";
import { swaggerSpec } from "./swagger";

const app = express();
const PORT = parseInt(process.env.PORT ?? "3001", 10);

// ── Docs (before Helmet so Swagger UI assets aren't blocked by CSP) ───────────
app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ── Security middleware ───────────────────────────────────────────────────────

// Helmet sets security-relevant HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
app.use(helmet());

// Rate limiting — prevents enumeration and brute-force against the member API
// PCI DSS v4 Req 6.4.1: protect public-facing web applications
const limiter = rateLimit({
  windowMs: 60 * 1000,     // 1 minute window
  max: 100,                 // 100 req/min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests — rate limit exceeded" },
});
app.use(limiter);

app.use(express.json({ limit: "10kb" })); // Prevent large payload attacks

// ── Routes ────────────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "membership-service", timestamp: new Date().toISOString() });
});

app.use("/members", membersRouter);

// 404 handler — don't leak route information
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Global error handler — never leak stack traces to clients
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("unhandled_error", { message: err.message, pci_req: "6.4" });
  res.status(500).json({ error: "Internal server error" });
});

// ── Startup ───────────────────────────────────────────────────────────────────

async function start() {
  try {
    await initSchema();
    logger.info("database_schema_initialised", { pci_req: "6.3" });

    app.listen(PORT, () => {
      logger.info("service_started", { port: PORT, pci_req: "6.4" });
    });
  } catch (err) {
    logger.error("service_start_failed", { error: (err as Error).message });
    process.exit(1);
  }
}

// Graceful shutdown
process.on("SIGTERM", async () => {
  logger.info("graceful_shutdown_initiated", { signal: "SIGTERM" });
  await disconnectProducer();
  process.exit(0);
});

start();
