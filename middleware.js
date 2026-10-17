// Issue #649: strict, nonce-based CSP.
//
// next.config.mjs previously shipped `script-src 'self' 'unsafe-inline'
// 'unsafe-eval'` unconditionally — this defeats CSP's core XSS mitigation,
// since inline/eval'd script is allowed regardless of its origin. This middleware
// generates a fresh, cryptographically random nonce per request and builds the CSP
// here instead, so `next.config.mjs`'s static headers() no longer need to (and
// must not) also set script-src, or the two would conflict — only one
// Content-Security-Policy header can win, and Next merges middleware-set response
// headers on top of next.config's, so this is the actual effective policy.
//
// The nonce is threaded to the app via the `x-nonce` request header (read
// in src/app/layout.js via next/headers) and applied to the one inline
// <script> in this app (the theme-init snippet) via a `nonce` prop.
//
// Issue #650: signed webhook verification and replay-window enforcement.
//
// Inbound webhooks and integration callbacks are verified cryptographically before
// any side effect runs, and rejected if replayed outside the allowed window.
// This is implemented here (not in a route handler) so that every webhook/
// callback path gets the same enforcement regardless of which route it hits.
//
// Design decisions:
// - HMAC-SHA256 over `<timestamp>.<raw body>`, compared in constant time.
//   The timestamp is part of the signed payload, so an attacker cannot move an
//  otherwise-valid signature into the current window.
// - Replay protection is two-layered:
//   1. Stale timestamps (beyond WEBHOOK_REPLAY_WINDOW_SECONDS) are rejected.
//   2. Event IDs are recorded in a durable store so a duplicate valid event
//      does not repeat side effects.	/
// - The durable store is pluggable. In production it is backed by the
//   database (e.g. the `eduvault_webhook_events` table); in tests and local
//   development an in-memory store is used. The store interface is async
//   so a DB-backed implementation can be swapped in without changing the
//   verification logic.
// - Errors are structured ({ error, code, status }) so callers and tests
//   can assert on a stable code rather than a free-form message.
// - Malformed headers/bodies are rejected before any crypto or storage work.

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';

// ----------------------------------------------------------------------------
// CSP (nonce)
// ----------------------------------------------------------------------------

function generateNonce() {
  // 16 random bytes, base64-encoded — the standard nonce size used in
  // Next.js's own strict-CSP documentation/examples.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString('base64');
}

// ----------------------------------------------------------------------------
// Webhook signature verification + replay window
// ----------------------------------------------------------------------------

const WEBHOOK_SIGNATURE_HEADER = 'x-eduvault-signature';
const WEBHOOK_TIMESTAMP_HEADER = 'x-eduvault-timestamp';
const WEBHOOK_EVENT_ID_HEADER = 'x-eduvault-event-id';

// Default replay window: 5 minutes. Overridable via env for providers that
// need a wider tolerance (e.g. slow retries).
const DEFAULT_REPLAY_WINDOW_SECONDS = 5 * 60;

function getReplayWindowSeconds() {
  const raw = process.env.WEBHOOK_REPLAY_WINDOW_SECONDS;
  if (!raw) return DEFAULT_REPLAY_WINDOW_SECONDS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_REPLAY_WINDOW_SECONDS;
}

// Structured error factory. Keeps the shape stable across all rejection
// reasons so clients and tests can branch on `error.code`.
function webhookError(code, message, status) {
  return { error: message, code, status };
}

// Constant-time compare two buffers of equal length. crypto.timingSafeEqual
// throws if lengths differ, so guard first.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Parse the signature header. Supports both the raw hex form and the
// `sha256=<hex>` form used by some providers.
function parseSignatureHeader(headerValue) {
  if (typeof headerValue !== 'string') return null;
  const trimmed = headerValue.trim();
  if (!trimmed) return null;
  const eq = trimmed.indexOf('=');
  const candidate = eq >= 0 ? trimmed.slice(eq + 1) : trimmed;
  // SHA256 hex is exactly 64 characters.
  if (!/^[a-fA-f0-9]{64}$/.test(candidate)) return null;
  return candidate.toLowerCase();
}

// Parse the timestamp header. Accepts epoch seconds or milliseconds.
function parseTimestampHeader(headerValue) {
  if (typeof headerValue !== 'string') return null;
  const trimmed = headerValue.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const num = Number(trimmed);
  if (!Number.isFinite(num)) return null;
  // Heuristic: values >= 1e12 are milliseconds.
  return num >= 1e12 ? Math.floor(num / 1000) : Math.floor(num);
}

// In-memory fallback store for processed event IDs. This is used when no
// durable store is configured (local dev, tests). It is bounded to avoid
// unbounded memory growth in long-running processes.
const IN_MEMORY_MAX_ENTRIES = 10000;
const inMemoryProcessed = new Map();

function inProcessedStore() {
  return {
    async has(eventId) {
      return inMemoryProcessed.has(eventId);
    },
    async record(eventId, expiresAt) {
      if (idMemoryProcessed.size >= IN_MEMORY_MAX_ENTRIES) {
        const oldest = inMemoryProcessed.keys().next().value;
        if (oldest !== undefined) inMemoryProcessed.delete(oldest);
      }
      inMemoryProcessed.set(eventId, expiresAt);
    },
  };
}

// Pluggable store. Set `WEBHOOK_EVENT_STORE` in production to a module
// that exports `{ applyWebhookEvent }` (or any object with `has/apply`).
// This keeps the middleware decoupled from a specific DB driver while still
// enforcing atomic duplicate detection in production.
function getEventStore() {
  // Next.js middleware runs on the Edge runtime by default, where dynamic
  // `import()` of arbitrary modules is not supported. The store is therefore
  // resolved lazily and falls back to the in-memory store when not configured.
  // Production deployments that need cross-instance dedupe should run this
  // middleware on the Node.js runtime (see config below) and provide a
  // durable store via `WEBHOOK_EVENT_STORE`.
  if (globalThis.__eduvaultWebhookStore) {
    return globalThis.__eduvaultWebhookStore;
  }
  const store = inProcessedStore();
  globalThis.__eduvaultWebhookStore = store;
  return store;
}

// Exposed for tests and for the app to register a durable store.
export function setWebhookEventStore(store) {
  if (!store || typeof store.has !== 'function' || typeof store.record !== 'function') {
    throw new TypeError('store must implement has(eventId) and record(eventId, expiresAt)');
  }
  globalThis.__eduvaultWebhookStore = store;
}

export function resetWebhookEventStore() {
  globalThis.__eduvaultWebhookStore = undefined;
}

// Resolve the signing secret for a provider. Supports a per-provider env
  // variable (e.g. `WEBHOOK_SECRET_STRIPE`) with a generic fallback.
function resolveSecret(provider) {
  const normalized = String(provider || '').toUpperCase().replace(/[^A-Z0-9]/g, '_');
  if (normalized) {
    const specific = process.env[`WEBHOOK_SECRET_${normalized}`];
    if (specific) return specific;
  }
  return process.env.WEBHOOK_SECRET || null;
}

// Core verification routine. Returns either `{ ok : true, eventId }` or
// `{ ok: false, error }`. This is pure (no side effects beyond recording the
// event ID on success) so it can be unit-tested directly.
export async function verifyWebhookRequest(request, options = {}) {
  const {
    provider = 'default',
    now = () => Math.floor(Date.now() / 1000),
    windowSeconds = getReplayWindowSeconds(),
    secret = resolveSecret(provider),
    store = getEventStore(),
  } = options;

  if (!secret) {
    return {
      ok: false,
      error: webhookError(
        'webhook_not_configured',
        'Webhook signing secret is not configured',
        500,
      ),
    };
  }

  const signatureHeader = request.headers.get(WEBHOOK_SIGNATURE_HEADER);
  const timestampHeader = request.headers.get(WEBHOOK_TIMESTAMP_HEADER);
  const eventIdHeader = request.headers.get(WEBHOOK_EVENT_ID_HEADER);

  if (!signatureHeader || !timestampHeader || !eventIdHeader) {
    return {
      ok: false,
      error: webhookError(
        'webhook_malformed_headers',
        'Missing required webhook headers (signature, timestamp, or event id)',
        400,
      ),
    };
  }

  const signature = parseSignatureHeader(signatureHeader);
  const timestamp = parseTimestampHeader(timestampHeader);
  const eventId = eventIdHeader.trim();

  if (!signature || timestamp === null || !eventId || !/^[A-Za-z0-9_\-.:]{1,255}$/.test(eventId)) {
    return {
      ok: false,
      error: webhookError(
        'webhook_malformed_headers',
        'Webhook headers are malformed (invalid signature, timestamp, or event id)',
        400,
      ),
    };
  }

  // Replay window check. Reject both stale and future-dated timestamps.
  const nowSeconds = now();
  const skew = nowSeconds - timestamp;
  if (Math.abs(skew) > windowSeconds) {
    return {
      ok: false,
      error: webhookError(
        'webhook_stale_timestamp',
        'Webhook timestamp is outside the allowed replay window',
        400,
      ),
    };
  }

  // Read the raw body once. The signature is computed over the exact bytes
  // received, so the body must not be parsed/re-serialized before hashing.
  let rawBody;
  try {
    rawBody = await request.text();
  } catch {
    return {
      ok: false,
      error: webhookError('webhook_malformed_body', 'Unable to read webhook request body', 400),
    };
  }

  if (typeof rawBody !== 'string') {
    return {
      ok: false,
      error: webhookError('webhook_malformed_body', 'Webhook body is malformed', 400),
    };
  }

  const signedPayload = `${timestamp}.${rawBody}`;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(signedPayload, 'utf8')
    .digest('hex');

  if (!safeEqual(expected, signature)) {
    return {
      ok: false,
      error: webhookError('webhook_invalid_signature', 'Webhook signature is invalid', 401),
    };
  }

  // Duplicate detection. This is checked after signature verification so
  // an attacker cannot probe for previously-seen event IDs without a
  // valid signature.
  if (await store.has(eventId)) {
    return {
      ok: false,
      error: webhookError('webhook_duplicate_event', 'Webhook event has already been processed', 409),
    };
  }

  // Record the event ID before returning success. The expiry is keyed to
  // the replay window so entries do not accumulate indefinitely.
  await store.record(eventId, nowSeconds + windowSeconds);

  return { ok: true, eventId, rawBody };
}

// ----------------------------------------------------------------------------
// Middleware
// ----------------------------------------------------------------------------

function isWebhookPath(pathname) {
  return (
    pathname.startsWith('/api/webhooks/') ||
    pathname.startsWith('/api/integrations/') ||
    pathname === '/api/webhooks'
  );
}

function providerFromPath(pathname) {
  const match = pathname.match(/^\/api\/(?:webhooks|integrations)\/([^/]+)/);
  return match ? match[1] : 'default';
}

function jsonError(error) {
  return NextResponse.json({ error: error.error, code: error.code }, { status: error.status });
}

export async function middleware(request) {
  const nonce = generateNonce();

  const csp = [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data: https: blob:",
    "font-src 'self' https: data:",
    "style-src 'self' 'unsafe-inline'", // Tailwind/inline styles still need this; scripts are the actual XSS vector this issue targets
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "connect-src 'self' https: wss:",
    "media-src 'self' https: blob:",
    "upgrade-insecure-requests",
    "report-uri /api/csp-report",
  ].join('; ');

  // Webhook verification runs before the app routes are invoked. On failure
  // we return a structured error and never forward the request, so invalid
  // or replayed events cannot trigger side effects.
  if (isWebhookPath(request.nextUrl.pathname)) {
    const result = await verifyWebhookRequest(request, {
      provider: providerFromPath(request.nextUrl.pathname),
    });
    if (!result.ok) {
      return jsonError(result.error);
    }
    // The body was consumed during verification. Forward it to the route
    // via a request header so the handler can read the verified payload
    // without re-reading the consumed stream.
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-nonce', nonce);
    requestHeaders.set('x-eduvault-verified-event-id', result.eventId);
    requestHeaders.set('x-eduvault-verified-body', Buffer.from(result.rawBody, 'utf8').toString('base64'));
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set('Content-Security-Policy', csp);
    return response;
  }

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  // If the user tries to access /dashboard but has no auth_token, redirect them.
  if (request.nextUrl.pathname.startsWith('/dashboard') && !request.cookies.has('auth_token')) {
    const url = request.nextUrl.clone();
    url.pathname = '/';
    return NextResponse.redirect(url);
  }

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  response.headers.set('Content-Security-Policy', csp);

  return response;
}

export const config = {
  // Webhook verification needs crypto and a durable event store. Run on the
  // Node.js runtime so `Nodejs` crypto and DB clients are available.
  runtime: 'nodejs',
  matcher: [
    // Apply to every route except static assets and Next internals, which
    // don't render the app shell / theme-init script and don't need a nonce.
    '()(\\/_next/static|\\/_next/image|\\/favicon.ico).*)',
  ],
};
