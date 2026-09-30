export const dynamic = "force-dynamic";
export const runtime = "nodejs";

import { NextResponse } from "next/server";
import { getDb } from "@/lib/mongodb";
import { requireAdmin } from "@/lib/api/auth";
import { createAuditCheckpoint, readAuditRecords, verifyAuditRecords } from "@/lib/backend/auditLedger";
import { requireApproval, validateApproval } from "@/lib/backend/maintainerApprovals";

const PROTECTED_ACTIONS = ["create_audit_checkpoint", "export_audit_ledger"];

function extractApproval(request, params) {
  const headerApproval = request.headers.get("x-maintainer-approval");
  if (headerApproval) {
    try {
      return JSON.parse(headerApproval);
    } catch {
      return { __invalidJson: true };
    }
  }
  if (params.approval) {
    try {
      return typeof params.approval === "string" ? JSON.parse(params.approval) : params.approval;
    } catch {
      return { __invalidJson: true };
    }
  }
  return null;
}

function stripApprovalParams(params) {
  const { approval, ...rest } = params;
  return rest;
}

async function enforceApproval(request, action, params, admin) {
  const approval = extractApproval(request, params);
  if (approval && approval.__invalidJson) {
    return { error: "Invalid approval payload: must be valid JSON.", status: 400 };
  }
  const result = await requireApproval({
    action,
    approval,
    actor: admin,
    scope: action,
  });
  if (!result.ok) {
    return { error: result.reason || "Approval required for this action.", status: result.status || 403 };
  }
  return { approval: result.approval };
}

export async function GET(request) {
  const admin = await requireAdmin(request);
  if (!admin) return NextResponse.json({ error: "Unauthorized. Admin access required." }, { status: 403 });

  try {
    const url = new URL(request.url);
    const rawParams = Object.fromEntries(url.searchParams.entries());
    const params = stripApprovalParams(rawParams);
    const limit = Math.min(Math.max(Number(params.limit) || 1000, 1), 5000);

    const guard = await enforceApproval(request, "export_audit_ledger", rawParams, admin);
    if (guard.error) {
      return NextResponse.json({ error: guard.error }, { status: guard.status });
    }

    const records = await readAuditRecords(await getDb(), { ...params, limit });
    const filtered = Object.keys(params).some((key) => ["action", "actor", "targetType", "operationId", "from", "to"].includes(key));
    return NextResponse.json({
      records,
      exportedAt: new Date().toISOString(),
      approval: guard.approval,
      verification: filtered ? { valid: null, note: "Verify an unfiltered export to validate the complete chain." } : verifyAuditRecords(records),
    });
  } catch (error) {
    console.error("Audit ledger export error:", error);
    return NextResponse.json({ error: "Failed to export audit ledger" }, { status: 500 });
  }
}

export async function POST(request) {
  const admin = await requireAdmin(request);
  if (!admin) return NextResponse.json({ error: "Unauthorized. Admin access required." }, { status: 403 });
  try {
    let body = {};
    try {
      body = await request.json();
    } catch {
      body = {};
    }
    const guard = await enforceApproval(request, "create_audit_checkpoint", body || {}, admin);
    if (guard.error) {
      return NextResponse.json({ error: guard.error }, { status: guard.status });
    }
    const checkpoint = await createAuditCheckpoint(await getDb());
    return NextResponse.json({ success: true, checkpoint, approval: guard.approval });
  } catch (error) {
    console.error("Audit ledger checkpoint error:", error);
    return NextResponse.json({ error: "Failed to create audit checkpoint" }, { status: 500 });
  }
}
