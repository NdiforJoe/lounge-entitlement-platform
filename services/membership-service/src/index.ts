import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { initSchema } from "./db/schema";
import { disconnectProducer } from "./kafka/producer";
import membersRouter from "./routes/members";

const app = express();
const PORT = parseInt(process.env.PORT ?? "3001", 10);

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
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ── Startup ───────────────────────────────────────────────────────────────────

async function start() {
  try {
    await initSchema();
    console.log("Database schema initialised");

    app.listen(PORT, () => {
      console.log(`membership-service listening on :${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start membership-service:", err);
    process.exit(1);
  }
}

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM received — shutting down gracefully");
  await disconnectProducer();
  process.exit(0);
});

start();
