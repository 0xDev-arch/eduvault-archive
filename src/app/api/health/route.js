export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { getDb } from "@/lib/mongodb";
import { pinata } from "@/lib/pinata";
import { verifyEmailConnection } from "@/lib/email";
import { withApiHardening } from "@/lib/api/hardening";
import { Server, rpc } from "@stellar/stellar-sdk";
import { HORIZON_URL, STELLAR_RPC_URL } from "@/lib/config/chain";
import { sanitizeErrorMessage } from "@/lib/status/publicStatusModel";

const CRITICAL_DEPENDENCIES = ["database"];
const OPTIONAL_DEPENDENCIES = ["email", "pinata"];
const CHAIN_DEPENDENCIES = ["stellar"];

function assessHealthStatus(services, criticalDeps) {
  const failed = Object.entries(services)
    .filter(([_, status]) => status !== "online")
    .map(([service]) => service);

  const criticalFailed = failed.filter((dep) =>
    criticalDeps.includes(dep)
  );

  if (criticalFailed.length > 0) {
    return {
      status: "unhealthy",
      statusCode: 503,
      failureReason: `Critical dependencies failed: ${criticalFailed.join(", ")}`,
    };
  }

  if (failed.length > 0) {
    return {
      status: "degraded",
      statusCode: 200,
      failureReason: `Some optional dependencies unavailable: ${failed.join(", ")}`,
    };
  }

  return {
    status: "healthy",
    statusCode: 200,
    failureReason: null,
  };
}

async function checkDatabaseHealth(db) {
  try {
    await db.command({ ping: 1 });
    return { status: "online", latencyMs: 0 };
  } catch (err) {
    return {
      status: "offline",
      error: sanitizeErrorMessage(err),
    };
  }
}

async function checkPinataHealth() {
  try {
    if (!process.env.PINATA_JWT) {
      return {
        status: "offline",
        error: "PINATA_JWT not configured",
      };
    }
    const start = Date.now();
    await pinata.testAuthentication();
    return { status: "online", latencyMs: Date.now() - start };
  } catch (err) {
    return {
      status: "offline",
      error: sanitizeErrorMessage(err),
    };
  }
}

async function checkEmailHealth() {
  try {
    const start = Date.now();
    await verifyEmailConnection();
    return { status: "online", latencyMs: Date.now() - start };
  } catch (err) {
    return {
      status: "offline",
      error: sanitizeErrorMessage(err),
    };
  }
}

async function checkStellarHealth() {
  try {
    const horizonStart = Date.now();
    const horizonServer = new Server(HORIZON_URL);
    await horizonServer.root();
    const horizonLatency = Date.now() - horizonStart;

    const rpcStart = Date.now();
    const rpcServer = new rpc.Server(STELLAR_RPC_URL);
    const health = await rpcServer.getHealth();
    const rpcLatency = Date.now() - rpcStart;

    if (health && health.status === "healthy") {
      return {
        status: "online",
        horizon: { status: "online", latencyMs: horizonLatency },
        rpc: { status: "online", latencyMs: rpcLatency },
      };
    } else {
      return {
        status: "degraded",
        rpc: {
          status: "degraded",
          error: `RPC status: ${health?.status || "unknown"}`,
          latencyMs: rpcLatency,
        },
        horizon: { status: "online", latencyMs: horizonLatency },
      };
    }
  } catch (err) {
    return {
      status: "offline",
      error: sanitizeErrorMessage(err),
    };
  }
}

export async function GET(request) {
  return withApiHardening(
    request,
    { route: "health-check", rateLimit: { limit: 60, windowMs: 60_000 } },
    async () => {
      try {
        const startTime = Date.now();
        const db = await getDb();

        const [databaseStatus, pinataStatus, emailStatus, stellarStatus] =
          await Promise.all([
            checkDatabaseHealth(db),
            checkPinataHealth(),
            checkEmailHealth(),
            checkStellarHealth(),
          ]);

        const services = {
          database: databaseStatus.status,
          pinata: pinataStatus.status,
          email: emailStatus.status,
          stellar: stellarStatus.status,
        };

        const { status, statusCode, failureReason } = assessHealthStatus(
          services,
          CRITICAL_DEPENDENCIES
        );

        const responseTime = Date.now() - startTime;

        return NextResponse.json(
          {
            status,
            timestamp: new Date().toISOString(),
            responseTimeMs: responseTime,
            dependencies: {
              critical: CRITICAL_DEPENDENCIES,
              optional: OPTIONAL_DEPENDENCIES,
              chain: CHAIN_DEPENDENCIES,
              status: {
                database: databaseStatus,
                pinata: pinataStatus,
                email: emailStatus,
                stellar: stellarStatus,
              },
            },
            failureReason,
          },
          { status: statusCode }
        );
      } catch (err) {
        return NextResponse.json(
          {
            status: "unhealthy",
            timestamp: new Date().toISOString(),
            error: "Failed to assess system health",
            failureReason: "Internal health check error",
          },
          { status: 503 }
        );
      }
    }
  );
}
