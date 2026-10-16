/**
 * src/lib/featureFlags.js
 *
 * Typed feature flag definitions with safe defaults (#797) and runtime
 * emergency-disablement overrides (#1018).
 *
 * Feature flags let maintainers stage rollout of risky behavior, compare
 * behavior between enabled/disabled cohorts, and disable a new path without a
 * redeploy (emergency rollback = flip the env var, not a code change).
 *
 * Design rules
 * ────────────
 * • Every flag has a hard-coded safe default. Missing or malformed
 *   configuration always falls back to that default — never to "enabled".
 * • Flags are read from `FEATURE_FLAG_<KEY>` environment variables so they
 *   can be changed per-environment (local / preview / production) without a
 *   code change.
 * • Runtime overrides (stored in MongoDB `feature_flag_overrides`) take
 *   precedence over env vars and are the basis for emergency disablement
 *   without a redeploy. Use `withFeatureGuard()` at route level to enforce.
 * • The registry below is the single source of truth. Adding a flag means
 *   adding one entry here; nothing else in the codebase needs to change.
 * • Synchronous `isFeatureFlagEnabled` is still safe in React components and
 *   contexts where a DB isn't available; async `resolveFeatureFlag` consults
 *   the override layer and is the correct choice for API route handlers.
 */

/**
 * @typedef {object} FeatureFlagDefinition
 * @property {string} key            - Registry key. The env var is `FEATURE_FLAG_<KEY>`.
 * @property {string} description    - What the flag controls, for operators.
 * @property {boolean} defaultValue  - Safe fallback when the env var is missing or malformed.
 * @property {string[]} [rolloutStages] - Ordered stage names for progressive rollout (informational).
 */

/**
 * The flag registry. Keys are UPPER_SNAKE_CASE; values carry the safe
 * default and a human-readable description.
 *
 * @type {Record<string, FeatureFlagDefinition>}
 */
export const FEATURE_FLAG_REGISTRY = Object.freeze({
  /**
   * Gates the critical lifecycle / recovery notifications (#776): purchase,
   * refund, entitlement, payout, suspension, and wallet-recovery events.
   * Default OFF — sending users notifications is new behavior, so it stays
   * off until a maintainer explicitly enables it per environment.
   */
  CRITICAL_LIFECYCLE_NOTIFICATIONS: {
    key: 'CRITICAL_LIFECYCLE_NOTIFICATIONS',
    description:
      'Sends in-app notifications for critical lifecycle and recovery events (purchases, refunds, entitlement changes, payouts, suspensions, wallet recovery).',
    defaultValue: false,
    rolloutStages: ['internal', 'beta', 'ga'],
  },

  /**
   * Gates the learner data export endpoint GET /api/learner-export (#790).
   * Default OFF — the export exposes purchase history and PII, so it stays
   * disabled until a maintainer explicitly enables it per environment.
   */
  LEARNER_DATA_EXPORT: {
    key: 'LEARNER_DATA_EXPORT',
    description:
      'Enables the authenticated learner data export endpoint (GET /api/learner-export).',
    defaultValue: false,
    rolloutStages: ['internal', 'beta', 'ga'],
  },

  /**
   * Gates the material archive/restore route (#1018).
   * Default OFF — archiving is new creator-facing behavior that changes
   * catalog visibility and search index state. Stays disabled until the
   * feature has been validated in a staging environment.
   *
   * Emergency disablement: set FEATURE_FLAG_ARCHIVE_MATERIAL=false in env,
   * or POST /api/admin/feature-flags with { key: "ARCHIVE_MATERIAL", enabled: false }
   * to override at runtime without a redeploy.
   */
  ARCHIVE_MATERIAL: {
    key: 'ARCHIVE_MATERIAL',
    description:
      'Enables the creator material archive/restore endpoint (POST /api/creator/materials/[id]/archive). Disabling immediately blocks new archive/restore operations without a redeploy.',
    defaultValue: false,
    rolloutStages: ['internal', 'beta', 'ga'],
  },
});

/** Env var prefix — a flag `FOO` is read from `FEATURE_FLAG_FOO`. */
const ENV_PREFIX = 'FEATURE_FLAG_';

/** Values treated as "enabled" (case-insensitive). */
const TRUTHY = new Set(['true', '1', 'yes', 'on']);
/** Values treated as "disabled" (case-insensitive). */
const FALSY = new Set(['false', '0', 'no', 'off']);

/**
 * Read a single flag's current value.
 *
 * Missing or malformed configuration falls back to the flag's safe default.
 * An unrecognized key throws — a typo in a call site should fail loudly at
 * development time rather than silently evaluating to a default.
 *
 * @param {string} key - Registry key (e.g. 'CRITICAL_LIFECYCLE_NOTIFICATIONS').
 * @returns {boolean}
 */
export function isFeatureFlagEnabled(key) {
  const definition = FEATURE_FLAG_REGISTRY[key];
  if (!definition) {
    throw new Error(`Unknown feature flag: ${key}`);
  }

  const raw = process.env[`${ENV_PREFIX}${key}`];
  if (raw === undefined || raw.trim() === '') {
    return definition.defaultValue;
  }

  const normalized = raw.trim().toLowerCase();
  if (TRUTHY.has(normalized)) return true;
  if (FALSY.has(normalized)) return false;

  // Malformed value — fall back to the safe default rather than guessing.
  return definition.defaultValue;
}

/**
 * Get the full definition plus the current evaluated value for one flag.
 *
 * @param {string} key
 * @returns {FeatureFlagDefinition & { enabled: boolean, source: 'env' | 'default' }}
 */
export function getFeatureFlag(key) {
  const definition = FEATURE_FLAG_REGISTRY[key];
  if (!definition) {
    throw new Error(`Unknown feature flag: ${key}`);
  }

  const raw = process.env[`${ENV_PREFIX}${key}`];
  const source = raw !== undefined && raw.trim() !== '' ? 'env' : 'default';
  return { ...definition, enabled: isFeatureFlagEnabled(key), source };
}

/**
 * List every registered flag with its current value. Used by the status
 * script and by tests.
 *
 * @returns {Array<FeatureFlagDefinition & { enabled: boolean, source: 'env' | 'default' }>}
 */
export function listFeatureFlags() {
  return Object.values(FEATURE_FLAG_REGISTRY).map((definition) =>
    getFeatureFlag(definition.key),
  );
}

// ─── Runtime override layer (#1018) ──────────────────────────────────────────
//
// Emergency disablement without a redeploy. An admin posts to
// POST /api/admin/feature-flags which writes a document to the
// `feature_flag_overrides` collection. `resolveFeatureFlag` reads that
// document and lets it win over the env-var value.
//
// Override priority (highest → lowest):
//   1. DB override  — set via admin API, survives restarts, instant effect
//   2. Env var      — set at deploy time, requires process restart to change
//   3. Registry default — hard-coded safe fallback
//
// The override layer is intentionally async-only. Synchronous helpers
// (isFeatureFlagEnabled, getFeatureFlag, listFeatureFlags) remain pure and
// side-effect-free so they stay safe in React and in non-DB contexts.

/** MongoDB collection that stores runtime overrides. */
export const OVERRIDE_COLLECTION = 'feature_flag_overrides';

/**
 * Read one flag's value, consulting the DB override layer first.
 *
 * Falls back gracefully if the DB is unavailable — the env-var / default
 * value is used so a DB outage never makes a disabled flag appear enabled.
 *
 * @param {string} key
 * @param {object} db   MongoDB db handle (from getDb())
 * @returns {Promise<{ enabled: boolean, source: 'override'|'env'|'default', overriddenBy?: string, reason?: string }>}
 */
export async function resolveFeatureFlag(key, db) {
  const definition = FEATURE_FLAG_REGISTRY[key];
  if (!definition) throw new Error(`Unknown feature flag: ${key}`);

  try {
    const override = await db
      .collection(OVERRIDE_COLLECTION)
      .findOne({ key });

    if (override && typeof override.enabled === 'boolean') {
      return {
        enabled: override.enabled,
        source: 'override',
        overriddenBy: override.updatedBy ?? null,
        reason: override.reason ?? null,
        updatedAt: override.updatedAt ?? null,
      };
    }
  } catch {
    // DB read failure — fall through to env / default. Never throw here;
    // a DB outage must not accidentally enable a disabled feature.
  }

  const envResult = getFeatureFlag(key);
  return { enabled: envResult.enabled, source: envResult.source };
}

/**
 * Write (upsert) a runtime override for one flag.
 *
 * @param {string}  key
 * @param {boolean} enabled
 * @param {object}  db
 * @param {object}  [meta]
 * @param {string}  [meta.updatedBy]  - actor identity (wallet address or user id)
 * @param {string}  [meta.reason]     - human-readable reason for the change
 * @returns {Promise<void>}
 */
export async function setFeatureFlagOverride(key, enabled, db, { updatedBy = null, reason = null } = {}) {
  const definition = FEATURE_FLAG_REGISTRY[key];
  if (!definition) throw new Error(`Unknown feature flag: ${key}`);
  if (typeof enabled !== 'boolean') throw new Error('enabled must be a boolean');

  await db.collection(OVERRIDE_COLLECTION).updateOne(
    { key },
    {
      $set: {
        key,
        enabled,
        updatedBy,
        reason,
        updatedAt: new Date(),
      },
    },
    { upsert: true },
  );
}

/**
 * Remove a runtime override, reverting to the env-var / default value.
 *
 * @param {string} key
 * @param {object} db
 * @returns {Promise<boolean>} true if an override was removed
 */
export async function clearFeatureFlagOverride(key, db) {
  const definition = FEATURE_FLAG_REGISTRY[key];
  if (!definition) throw new Error(`Unknown feature flag: ${key}`);

  const result = await db.collection(OVERRIDE_COLLECTION).deleteOne({ key });
  return (result?.deletedCount ?? 0) > 0;
}

/**
 * List all flags with their resolved values (DB override wins over env/default).
 * Used by the admin status API.
 *
 * @param {object} db
 * @returns {Promise<Array>}
 */
export async function listFeatureFlagsResolved(db) {
  const keys = Object.keys(FEATURE_FLAG_REGISTRY);
  return Promise.all(keys.map(async (key) => {
    const def = FEATURE_FLAG_REGISTRY[key];
    const resolved = await resolveFeatureFlag(key, db);
    return { ...def, ...resolved };
  }));
}

// ─── Route-level feature guard (#1018) ───────────────────────────────────────

/**
 * Wrap a Next.js route handler behind a feature flag.
 *
 * When the flag is disabled (accounting for DB overrides) the route responds
 * with 503 and a stable error body immediately, without running the handler.
 * This is the standard "guardrail" pattern for new features in eduvault-archive.
 *
 * Usage:
 *   export const GET = withFeatureGuard('ARCHIVE_MATERIAL', handler);
 *
 * @param {string}   flagKey   - Registry key
 * @param {Function} handler   - Async (request, context) => Response
 * @returns {Function}         - Wrapped async (request, context) => Response
 */
export function withFeatureGuard(flagKey, handler) {
  const definition = FEATURE_FLAG_REGISTRY[flagKey];
  if (!definition) throw new Error(`Unknown feature flag: ${flagKey}`);

  return async function guardedHandler(request, context) {
    // Attempt DB-backed resolution; fall back gracefully if DB unavailable.
    let enabled = isFeatureFlagEnabled(flagKey);
    try {
      const { getDb } = await import('./mongodb.js');
      const db = await getDb();
      const resolved = await resolveFeatureFlag(flagKey, db);
      enabled = resolved.enabled;
    } catch {
      // DB unavailable — use env/default value already set above.
    }

    if (!enabled) {
      const { NextResponse } = await import('next/server');
      return NextResponse.json(
        {
          error: {
            code: 'FEATURE_DISABLED',
            message: `This feature is not currently enabled on this deployment.`,
            retryable: false,
            supportAction: 'Contact an administrator to enable this feature.',
          },
        },
        { status: 503 },
      );
    }

    return handler(request, context);
  };
}
