export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { auditLog } from "@/lib/api/audit";
import { withApiHardening } from "@/lib/api/hardening";
import { validateMaterialPayload, validateMaterialUpdatePayload, validateChangeReason, validateExpectedVersion } from "@/lib/api/validation";
import { getUserFromCookie } from "@/lib/api/auth";
import { getDb } from "@/lib/mongodb";
import { ObjectId } from "mongodb";
import { buildMaterialHistoryEntry, EDITABLE_MATERIAL_FIELDS } from "@/lib/backend/schemaContracts";
import { enqueueMaterialSearchProjection } from "@/lib/backend/materialSearchProjection";
import { evaluateAndQueueListing } from "@/lib/backend/manipulationScoring";
import { invalidateCatalogCache } from "@/lib/cache/redis";
import {
  readRecord,
  writeRecord,
  negotiateSchemaVersion,
  schemaResponseHeaders,
  UnsupportedSchemaVersionError,
} from "@/lib/backend/schemaCompat";

export const runtime = "nodejs";

function sanitizeMaterial(doc) {
  if (!doc) return doc;
  const { storageKey, fileUrl, metadataUrl, ...safe } = doc;
  return safe;
}

export async function POST(request) {
  return withApiHardening(
    request,
    { route: "materials", rateLimit: { limit: 40, windowMs: 60_000 } },
    async () => {
      try {
        const user = await getUserFromCookie(request);
        if (!user) {
          auditLog({ event: "auth_failed", route: "materials", method: "POST", status: 401 });
          return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        // #803: an older client may pin the shape it knows via X-Schema-Version.
        const negotiation = negotiateSchemaVersion(request, "materials");
        const material = validateMaterialPayload(await request.json());

        const db = await getDb();

        let userAddress = user.walletAddress || user.address || null;
        if (!userAddress && user.sub) {
          try {
            const dbUser = await db.collection("users").findOne({ _id: new ObjectId(user.sub) });
            userAddress = dbUser?.walletAddress || dbUser?.walletAddressLower || null;
          } catch (e) {
            console.warn("User lookup failed while creating material:", e?.message || e);
          }
        }

        const doc = writeRecord(
          "materials",
          {
            userAddress,
            ...material,
            version: 1,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
          { version: negotiation.version }
        );

        const result = await db.collection("materials").insertOne(doc);
        const assessment = await evaluateAndQueueListing(db, { _id: result.insertedId, ...doc });
        await enqueueMaterialSearchProjection({
          db,
          material: { _id: result.insertedId, ...doc, ...(assessment.flagged ? { moderationStatus: "pending_review" } : {}) },
          reason: "material_created",
        });
        await invalidateCatalogCache();
        auditLog({ event: "material_created", route: "materials", method: "POST", status: 201, actor: user.sub });
        return NextResponse.json(
          { success: true, materialId: result.insertedId, ...sanitizeMaterial(doc) },
          { status: 201, headers: schemaResponseHeaders("materials", negotiation.version) }
        );
      } catch (err) {
        if (err.name === "ValidationError") throw err;
        if (err instanceof UnsupportedSchemaVersionError) {
          return NextResponse.json({ error: err.message, collection: err.collection, latest: err.latest }, { status: 400 });
        }
        auditLog({ event: "material_create_failed", route: "materials", method: "POST", status: 500, reason: err.message });
        return NextResponse.json({ error: "Server error" }, { status: 500 });
      }
    }
  );
}

export async function GET(request) {
  return withApiHardening(
    request,
    { route: "materials", rateLimit: { limit: 80, windowMs: 60_000 } },
    async () => {
      try {
        const user = await getUserFromCookie(request);
        if (!user) {
          auditLog({ event: "auth_failed", route: "materials", method: "GET", status: 401 });
          return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        // #803: legacy documents are upgraded in-memory to the requested
        // shape, so old records stay readable before a backfill reaches them.
        const negotiation = negotiateSchemaVersion(request, "materials");
        const db = await getDb();
        const userAddress = user.walletAddress || user.address || user.id;
        const items = await db
          .collection("materials")
          .find({ userAddress })
          .sort({ createdAt: -1 })
          .toArray();

        const normalized = items.map((doc) =>
          readRecord("materials", sanitizeMaterial(doc), { targetVersion: negotiation.version })
        );
        return NextResponse.json(normalized, { headers: schemaResponseHeaders("materials", negotiation.version) });
      } catch (err) {
        if (err.name === "ValidationError") throw err;
        if (err instanceof UnsupportedSchemaVersionError) {
          return NextResponse.json({ error: err.message, collection: err.collection, latest: err.latest }, { status: 400 });
        }
        auditLog({ event: "material_list_failed", route: "materials", method: "GET", status: 500, reason: err.message });
        return NextResponse.json({ error: "Server error" }, { status: 500 });
      }
    }
  );
}

export async function PUT(request) {
  return withApiHardening(
    request,
    { route: "materials", rateLimit: { limit: 40, windowMs: 60_000 } },
    async () => {
      try {
        const user = await getUserFromCookie(request);
        if (!user) {
          auditLog({ event: "auth_failed", route: "materials", method: "PUT", status: 401 });
          return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const url = new URL(request.url);
        const materialId = url.searchParams.get("id");
        if (!materialId || !ObjectId.isValid(materialId)) {
          return NextResponse.json({ error: "Invalid material ID" }, { status: 400 });
        }

        const body = await request.json();
        const updates = validateMaterialUpdatePayload(body);
        const changeReason = validateChangeReason(body.changeReason);
        const expectedVersion = validateExpectedVersion(
          body.expectedVersion ?? body.version ?? request.headers.get("if-match")?.replace(/["\s]/g, '')
        );

        const db = await getDb();
        const userAddress = user.walletAddress || user.address || user.id;

        const existing = await db.collection("materials").findOne({ _id: new ObjectId(materialId) });
        if (!existing) {
          return NextResponse.json({ error: "Material not found" }, { status: 404 });
        }

        const isOwner =
          existing.userAddress === userAddress ||
          (existing.userAddress && userAddress && existing.userAddress.toLowerCase() === userAddress.toLowerCase());
        const isAdmin = user.role === "admin" || user.isAdmin === true;

        if (!isOwner && !isAdmin) {
          auditLog({ event: "material_update_forbidden", route: "materials", method: "PUT", status: 403, actor: user.sub });
          return NextResponse.json({ error: "Forbidden: not the material owner" }, { status: 403 });
        }

        const currentVersion = existing.version || 1;

        // Optimistic concurrency control check if client specified an expected version
        if (expectedVersion !== null && expectedVersion !== currentVersion) {
          auditLog({
            event: "material_update_conflict",
            route: "materials",
            method: "PUT",
            status: 409,
            actor: user.sub,
            materialId,
            currentVersion,
            expectedVersion,
          });
          return NextResponse.json(
            {
              error: "Conflict: This listing has been modified by another session. Please reload to see the latest changes.",
              code: "CONCURRENCY_CONFLICT",
              currentVersion,
              expectedVersion,
              conflictFields: Object.keys(updates),
            },
            { status: 409 }
          );
        }

        const now = new Date();
        const nextVersion = currentVersion + 1;
        const updateDoc = {
          ...updates,
          updatedAt: now,
          updatedBy: userAddress,
          version: nextVersion,
          searchVersion: nextVersion,
        };

        // Atomic Compare-And-Swap (CAS) update to prevent lost updates from concurrent writes
        const filter = {
          _id: new ObjectId(materialId),
          $or: [
            { version: currentVersion },
            ...(currentVersion === 1 ? [{ version: { $exists: false } }] : []),
          ],
        };

        const result = await db.collection("materials").findOneAndUpdate(
          filter,
          { $set: updateDoc },
          { returnDocument: "after" }
        );

        const updatedMaterial = result?.value || result;

        if (!updatedMaterial) {
          // Concurrently updated by another writer between findOne and findOneAndUpdate
          const fresh = await db.collection("materials").findOne({ _id: new ObjectId(materialId) });
          if (!fresh) {
            return NextResponse.json({ error: "Material not found" }, { status: 404 });
          }
          auditLog({
            event: "material_update_conflict",
            route: "materials",
            method: "PUT",
            status: 409,
            actor: user.sub,
            materialId,
            currentVersion: fresh.version || 1,
            expectedVersion: currentVersion,
          });
          return NextResponse.json(
            {
              error: "Conflict: This listing has been modified by another session. Please reload to see the latest changes.",
              code: "CONCURRENCY_CONFLICT",
              currentVersion: fresh.version || 1,
              expectedVersion: currentVersion,
              conflictFields: Object.keys(updates),
            },
            { status: 409 }
          );
        }

        const assessment = await evaluateAndQueueListing(db, updatedMaterial, { now });
        if (assessment.flagged) updatedMaterial.moderationStatus = "pending_review";
        await enqueueMaterialSearchProjection({
          db,
          material: updatedMaterial,
          reason: "material_updated",
          now,
        });

        const historyEntry = buildMaterialHistoryEntry({
          materialId,
          previousDoc: existing,
          update: updates,
          updatedBy: userAddress,
          changeReason,
          source: isAdmin ? "admin" : "creator",
        });

        await db.collection("material_history").insertOne(historyEntry);
        await invalidateCatalogCache();

        auditLog({ event: "material_updated", route: "materials", method: "PUT", status: 200, actor: user.sub, materialId });
        return NextResponse.json(sanitizeMaterial(updatedMaterial));
      } catch (err) {
        if (err.name === "ValidationError") throw err;
        auditLog({ event: "material_update_failed", route: "materials", method: "PUT", status: 500, reason: err.message });
        return NextResponse.json({ error: "Server error" }, { status: 500 });
      }
    }
  );
}

export async function PATCH(request) {
  return PUT(request);
}
