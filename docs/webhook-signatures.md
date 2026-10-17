# Webhook Signatures

> **Canonical serialization:** Signed webhook payloads are serialized using the
> canonical JSON rules defined in
> [`docs/canonical-serialization.md`](canonical-serialization.md). The
> `rawBody` you verify against MUST be the canonical byte sequence.

EduVault delivers outbound webhooks to creator-configured endpoints for
purchase, refund, entitlement, and dispute lifecycle events. Every delivery
is signed so the receiving server can verify the payload was produced by
EduVault and has not been tampered with in transit.

EduVault also accepts inbound webhooks and integration callbacks from
supported providers. These inbound requests are verified with the same
HMAC-SHA256 scheme and the same replay window, and their event IDs are
persisted to prevent replays. See
[Inbound Webhook Verification](@inbound-webhook-verification).

See [`docs/API_REFERENCE.md`](API_REFERENCE.md) for the stable error codes
(`EVT_WEBHOOK_*`) returned when signature verification or delivery fails.

---

## Signing Algorithm

Signatures use **HMAC-SHA256**. The signing input is a deterministic
concatenation of the delivery timestamp and the raw request body:

```
signingInput = timestamp + "." + rawBody
```

where:

- `timestamp` is the Unix epoch seconds value sent in the
  `X-EduVault-Timestamp` (or provider-equivalent) header (decimal string,
  no fractional part).
- `rawBody` is the **exact bytes** of the HTTP request body before any
  parsing.

The `rawBody` is produced by the canonical serializer, which guarantees that
equivalent payloads (same logical values, different key order, whitespace,
or casing) produce byte-identical output. Verifiers MUST NOT re-serialize
the parsed JSON to reconstruct `rawBody`; doing so may produce a different
byte sequence and cause `EVT_WEBHOOK_001`.

The HMAC key is the creator's `webhookSigningSecret` stored in the `users`
collection. For inbound provider webhooks, the key is the provider secret
from the integration configuration. During secret rotation, both the current
secret (`webhookSigningSecret`) and the previous one (`webhookSigningSecretPrevious`)
are active for a short overlap window; the delivery is accepted if **either**
signature verifies (see [Secret Rotation](@secret-rotation)).

---

## Request Headers

Every webhook delivery includes these headers:

| Header                 | Example              | Description                                             |
| ---------------------- | ------------------- | ------------------------------------------------------------ |
| `X-EduVault-Signature` | `sha256=a1b2c3...`   | Hex-encoded HMAC-SHA256 signature, prefixed with `sha256=`. |
| `X-EduVault-Timestamp` | `1727222400`         | Unix epoch seconds at delivery time.                        |
| `X-EduVault-Event`     | `purchase.completed` | Event type (matches the `event` field in the payload body).     |
| `X-EduVault-Delivery`  | `01j9abc...`         | Globally unique delivery ID for idempotency checks.         |
| `Content-Type`         | `application/json`   | Always JSON.                                                 |

---

## Verification Steps

1. **Extract headers** — read `X-EduVault-Timestamp`, `X-EduVault-Signature`,
   and the raw request body before JSON-parsing.

2. **Reject stale timestamps** — if `|now() - timestamp| > 300` seconds
   (5 minutes), reject with HTTP 401 and error code `EVT_WEBHOOK_002`.
   This prevents replay attacks. A timestamp that is not a valid integer is
   treated as stale (`EVT_WEBHOOK_002`).

3. **Compute expected signature**:

   ```
   signingInput = timestamp + "." + rawBody
   expected = "sha256=" + hex(HMAC-SHA256(signingSecret, signingInput))
   ```

4. **Compare signatures** using a constant-time equality function to prevent
   timing attacks. Do **not** use a naive string equality (`==`).

5. **Accept if either secret matches** during a rotation window (see
   [Secret Rotation](@secret-rotation)).

6. **Deduplicate by event ID.** After the signature and timestamp are
   verified, persist the event ID to the processed-events store before
   applying side effects. If the event ID was already processed, return
   HTTP 200 without repeating side effects (see
   [Idempotency and Replay Prevention](@idempotency-and-replay-prevention)).

7. **Return 200** on success. Any non-2xx response is treated as a delivery
   failure and triggers retries with exponential backoff.

### Reference Implementation (Node.js)

```js
import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Verify an incoming EduVault webhook request.
 *
 * @param {string}        rawBody     Raw request body string (before JSON.parse).
 * @param {string}        timestamp   Value of X-EduVault-Timestamp header.
 * @param {string}        signature   Value of X-EduVault-Signature header.
 * @param {string}        secret      Creator's current webhookSigningSecret.
 * @param {string | null} prevSecret  Creator's previous secret (during rotation), or null.
 * @param {number}        [toleranceSec=300] Max allowed timestamp drift in seconds.
 * @returns {boolean} true if the signature is valid and the timestamp is fresh.
 */
export function verifyWebhookSignature(
  rawBody,
  timestamp,
  signature,
  secret,
  prevSecret = null,
  toleranceSec = 300,
) {
  // Step 1: Check timestamp freshness.
  const ts = parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Math.abs(Date.now() / 1000 - ts) > toleranceSec) {
    return false;
  }

  // Step 2: Build the signing input.
  const signingInput = `${timestamp}.${rawBody}`;

  // NOTE: `rawBody` must already be the canonical serialization. Do not
  // call JSON.stringify(JSON.parse(rawBody)) here — that would change the
  // byte sequence and break verification.

  // Step 3: Compute expected signature(s).
  function computeSig(key) {
    return (
      "sha256=" + createHmac("sha256", key).update(signingInput).digest("hex")
    );
  }

  // Step 4: Constant-time comparison.
  function safeEqual(a, b) {
    if (a.length !== b.length) return false;
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

  if (safeEqual(computeSig(secret), signature)) return true;
  if (prevSecret && safeEqual(computeSig(prevSecret), signature)) return true;
  return false;
}
```

The function above returns a boolean for the cryptographic check. The HTTP
handler MUST distinguish between a stale timestamp and a bad signature so it
can return the correct structured error code. The reference handler below
shows the complete flow including replay deduplication.

### Reference Implementation (Python)

```py
import hashlib
import hmac
import time

def verify_webhook_signature(
    raw_body: bytes,
    timestamp: str,
    signature: str,
    secret: str,
    prev_secret: str | None = None,
    tolerance_sec: int = 300,
) -> bool:
    """Verify an EduVault webhook signature."""
    try:
        ts = int(timestamp)
    except ValueError:
        return False

    if abs(time.time() - ts) > tolerance_sec:
        return False  # EVT_WEBHOOK_002

    signing_input = f"{timestamp}.".encode() + raw_body

    # NOTE: raw_body must already be the canonical serialization. Do not
    # re-serialize the parsed JSON — that would change the byte sequence
    # and break verification.

    def compute(key: str) -> str:
        mac = hmac.new(key.encode(), signing_input, hashlib.sha256)
        return "sha256=" + mac.hexdigest()

    if hmac.compare_digest(compute(secret), signature):
        return True
    if prev_secret and hmac.compare_digest(compute(prev_secret), signature):
        return True
    return False
```

---

## Inbound Webhook Verification

Inbound webhooks and integration callbacks arrive at the EduVault API
boundary and are processed by the webhook intgestion handler. The flow is
strictly ordered so that no side effect is applied before the request is
authenticated and deduplicated:

1. Read the raw request body as a Buffer before any JSON parsing.
2. Validate the required headers are present and well-formed.
3. Reject stale timestamps (`EVT_WEBHOOK_002`).
4. Verify the signature in constant time (`EVT_WEBHOOK_001`).
5. Parse the JSON and validate the envelope shape (`EVT_WEBHOOK_009` for
   malformed or duplicate-key payloads).
6. Deduplicate by event ID and apply side effects atomically.

The event ID is the `deliveryId` in the payload envelope (for providers
that do not use the EduVault envelope, the provider's event ID header is
used). The ID is scoped to the provider and the creator so two different
creators can safely receive the same provider event ID.

### Structured Errors

Invalid, replayed, and malformed inbound webhooks return a stable JSON
error envelope:

```json
{
  "error": {
    "code": "EVT_WEBHOOK_001",
    "message": "Invalid webhook signature.",
    "details": {
      "reason": "signature_mismatch"
    }
  }
}
```

| Status | Code               | When it is returned                                         |
| ------ | ------------------- | --------------------------------------------------------------- |
| 401   | `EVT_WEBHOOK_001`   | Signature header is missing, malformed, or does not match any active secret. |
| 401   | `EVT_WEBHOOK_002`   | Timestamp header is missing, non-integer, or outside the 300s window.    |
| 409   | `EVT_WEBHOOK_003`   | Event ID was already processed (duplicate).                        |
| 400   | `EVT_WEBHOOK_009`   | Payload is not valid canonical JSON or contains duplicate keys.      |

Duplicate deliveries are idempotent: a duplicate valid event is either
acknowledged with HTTP 200 and no side effects, **or** rejected with 409
`EVT_WEBHOOK_003`, depending on the provider's retry semantics. The EduVault
default is to return 409 so duplicates are visible in monitoring; providers
that retry on 409 can be configured to receive 200 instead.

## Idempotency and Replay Prevention

Processed event IDs are persisted in the `webhookProcessedEvents` collection.
Each document is written with a unique compound index on
`(provider, scopeId, eventId)` so the insert is atomic and concurrent
butters cannot both succeed.

Document shape:

```json
{
  "provider": "eduvault",
  "scopeId": "creator_123",
  "eventId": "01j9abc123",
  "eventType": "purchase.completed",
  "receivedAt": "2024-09-25T00:00:00.000Z",
  "payloadHash": "0b0b0b0b...",
  "expiresAt": "2024-10-25T00:00:00.000Z"
}
```

Implementation rules:

- The dedupe record is inserted **within the same transaction** as the
  side effects. If the insert conflicts on the unique index, the
  transaction is aborted and the request is treated as a duplicate.
- The store is authoritative: in-memory caches may optimize the check but
  MUST not replace the persistent unique constraint.
- Records are retained for at least the maximum provider retry window (30
  days by default) and then expire via `expiresAt`.
- Stale events are rejected before the dedupe check, so an attacker cannot
  poison the dedupe store with unauthenticated event IDs.

### Reference Handler (Node.js)

```js
import { createHmac, timingSafeEqual } from "node:crypto";

const TOLERANCE_SEC = 300;

function computeSignature(secret, signingInput) {
  return (
    "sha256=" + createHmac("sha256", secret).update(signingInput).digest("hex")
  );
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function errorResponse(status, code, message, reason) {
  return {
    status,
    body: { error: { code, message, details: reason ? { reason } : {} } },
  };
}

/**
 * Handle an inbound webhook. Returns a structured result that the HTTP adapter
 * translates into a response. Side effects are applied only after verification
 * and deduplication succeed.
 *
 * @param {object} req
 * @param {Buffer} req.rawBody
 * @param {Record<string, string?} req.headers
 * @param {object} deps
 * @param {(provider: string, scopeId: string) => Promise<{secret: string, prevSecret?: string | null}>} deps.loadSecret
 * @param {(key: object) => Promise<boolean>} deps.recordEvent Inserts the dedupe record; resolves false on conflict.
 * @param {(key: object) => Promise<void>} deps.applySideEffects
 */
export async function handleInboundWebhook(req, deps) {
  const headers = req.headers ?? {};
  const timestamp = headers["x-eduvault-timestamp"];
  const signature = headers["x-eduvault-signature"];
  const provider = headers["x-eduvault-provider"] ?? "eduvault";
  const scopeId = headers["x-eduvault-scope-id"];

  if (!timestamp || !signature || !scopeId) {
    return errorResponse(
      401,
      "EVT_WEBHOOK_001",
      "Invalid webhook signature.",
      "missing_headers",
    );
  }

  // Stale timestamps are rejected before any cryptographic work.
  const ts = Number(timestamp);
  if (!Number.isInteger(ts) || Math.abs(Date.now() / 1000 - ts) > TOLERANCE_SEC) {
    return errorResponse(
      401,
      "EVT_WEBHOOK_002",
      "Webhook timestamp is stale.",
      "stale_timestamp",
    );
  }

  const { secret, prevSecret = null } = await deps.loadSecret(provider, scopeId);
  const rawBody = req.rawBody.toString("utf=8");
  const signingInput = `${timestamp}.${rawBody}`;

  const matches =
    safeEqual(computeSignature(secret, signingInput), signature) ||
    (prevSecret !== null &&
      safeEqual(computeSignature(prevSecret, signingInput), signature));

  if (!matches) {
    return errorResponse(
      401,
      "EVT_WEBHOOK_001",
      "Invalid webhook signature.",
      "signature_mismatch",
    );
  }

  // Parse only after the signature has been verified.
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return errorResponse(
      400,
      "EVT_WEBHOOK_009",
      "Webhook payload is not valid JSON.",
      "malformed_payload",
    );
  }

  const eventId = payload.deliveryId ?? headers["x-eduvault-delivery"];
  if (typeof eventId !== "string" || eventId.length === 0) {
    return errorResponse(
      400,
      "EVT_WEBHOOK_009",
      "Webhook payload is missing an event ID.",
      "missing_event_id",
    );
  }

  const key = { provider, scopeId, eventId };
  const inserted = await deps.recordEvent(key);
  if (!inserted) {
    return errorResponse(
      409,
      "EVT_WEBHOOK_003",
      "Webhook event was already processed.",
      "duplicate_event",
    );
  }

  await deps.applySideEffects(key, payload);
  return { status: 200, body: { ok: true } };
}
```

The adapter that wires this handler into the app MUST provide the raw request
body (for example by disabling the global JSON body parser for the webhook
route and reading the stream into a Buffer). A re-serialized body will fail
verification and return `EVT_WEBHOOK_001`.

---

## Secret Rotation

To rotate a signing secret without dropping deliveries:

1. Move the current value of `webhookSigningSecret` into
   `webhookSigningSecretPrevious`.
2. Set `webhookSigningSecret` to the new secret.
3. Verify deliveries using both secrets for the overlap window (at
   least the maximum retry duration, typically 15 minutes).
4. Clear `webhookSigningSecretPrevious` once the overlap window ends.

Rotation is operationally safe because verification accepts either secret
during the overlap. Never remove the previous secret before the overlap
window closes, or in-flight deliveries signed with the old secret will fail
with `EVT_WEBHOOK_001`.

---

## Payload Shape

All event payloads follow a common envelope:

```json
{
  "event":     "purchase.completed",
  "deliveryId": "01j9abc123...",
  "timestamp":  1727222400,
  "data": { ... }
}
```

The envelope is serialized canonically: object keys are sorted lexicographically
by Unicode code point, strings are NFC-normalized, numbers use the shortest
round-trippable decimal form, and no insignificant whitespace is emitted.
See [`docs/canonical-serialization.md`](canonical-serialization.md) for the
full rules and normalization table.

| Field        | Type     | Description                                        |
| ------------ | -------- | ----------------------------------------------------------- |
| `event`      | `string` | Event type identifier (see [Event Types](#event-types)). |
| `deliveryId` | `string` | Unique delivery ID. Use for idempotency deduplication.   |
| `timestamp`  | `number` | Unix epoch seconds matching `X-EduVault-Timestamp`.      |
| `data`       | `object` | Event-specific payload.                                  |

### Normalization rules for `data`

The envelope and every nested `data` object must be serialized canonically
before hashing, signing, or comparison. See
[Canonical Serialization](#canonical-serialization).

- **Key ordering:** all object keys are sorted lexicographically before
  serialization. Producers and consumers MUST NOT rely on insertion order.
- **Whitespace:** no spaces, tabs, or newlines are emitted between tokens.
- **Casing:** event names, status enums, and resolution enums are
  case-sensitive and MUST be emitted in their canonical form (e.g.
  `purchase.completed`, `Active`, `RefundBuyer`). Free-text fields are
  preserved verbatim after NFC normalization.
- **Numeric precision:** monetary amounts (`grossAmount`, `platformFee`,
  `sellerNet`, `unitPrice`, `totalPaid`, `refundAmount`) are serialized as
  **decimal strings** of the smallest indivisible unit. They MUST NOT be
  emitted as JSON numbers, to avoid IEEE754 precision loss.
- **Ledger numbers** (`openedLedger`, `resolvedLedger`) are integers and
  MUST be emitted as JSON numbers within the safe integer range.
- **Hashes and addresses** (`metadataHash`, `rightsHash`, `materialId`,
  `*Address`, `asset`) are lowercase hex or canonical Stellar strkey form.
---

## Event Types

### `purchase.completed`

Fired when a buyer successfully purchases a material.

```json
{
  "event": "purchase.completed",
  "deliveryId": "01j9...",
  "timestamp": 1727222400,
  "data": {
    "purchaseId": "42",
    "materialId": "abc123...",
    "buyerAddress": "GBUY...",
    "sellerAddress": "GSEL...",
    "asset": "GDUSDC...",
    "grossAmount": "1000000",
    "platformFee": "50000",
    "sellerNet": "950000",
    "saleTermsVersion": 1,
    "metadataHash": "0b0b0b...",
    "rightsHash": "1c1c1c...",
    "transactionId": "550e8400-...",
    "entitlementActive": true
  }
}
```

### `purchase.bulk_completed`

Fired when a bulk-license purchase completes.

```json
{
  "event": "purchase.bulk_completed",
  "data": {
    "purchaserId": "GPUR...",
    "materialId": "abc123...",
    "recipientCount": 5,
    "unitPrice": "1000000",
    "totalPaid": "5000000",
    "asset": "GDUSDC...",
    "firstPurchaseId": "10"
  }
}
```

### `purchase.refunded`

Fired when a refund is issued for a purchase.

```json
{
  "event": "purchase.refunded",
  "data": {
    "purchaseId": "42",
    "materialId": "abc123...",
    "buyerAddress": "GBUY...",
    "asset": "GDUSDC...",
    "refundAmount": "950000",
    "entitlementRevoked": true
  }
}
```

### `dispute.opened`

Fired when a buyer opens a dispute on a purchase.

```json
{
  "event": "dispute.opened",
  "data": {
    "purchaseId": "42",
    "materialId": "abc123...",
    "openerAddress": "GBUY...",
    "reason": "Material does not match description.",
    "openedLedger": 12345678
  }
}
```

### `dispute.resolved`

Fired when an admin resolves a dispute.

```json
{
  "event": "dispute.resolved",
  "data": {
    "purchaseId": "42",
    "materialId": "abc123...",
    "resolution": "RefundBuyer",
    "resolvedLedger": 12350000
  }
}
```

### `material.sale_terms_updated`

Fired when a creator updates a material's price or payout configuration.

```json
{
  "event": "material.sale_terms_updated",
  "data": {
    "materialId": "abc123...",
    "creatorAddress": "GCRE...",
    "saleTermsVersion": 2,
    "status": "Active"
  }
}
```

---

## Canonical Serialization

Payloads that are hashed, signed, compared, or verified must be serialized
canonically so that equivalent payloads always produce identical bytes. This
applies to webhook signing inputs, `metadataHash` / `rightsHash` values, and any payload stored or re-verified by EduVault.

### Rules

1. **UTF-8 encoding.** All strings are encoded as UTF-8. No BOM.

2. **Object key ordering.** Object keys are sorted by Unicode code point
   (lexicographic, ascending) at every nesting level. Arrays preserve their
   original order.

3. **No insignificant whitespace.** No spaces, tabs, or newlines between
   tokens. Separators are exactly `,` and `:`.

4. **String normalization.** Strings are normalized to Unicode NFC. Control
   characters are escaped using the shortest valid JSON escape (`\n`, `\t`,
   `\"`, `\\`, `\u00XX`). Non-ASCII characters are emitted as literal UTF-8,
   not `\u` escapes.

5. **Key casing.** Keys are case-sensitive and preserved as-is. Duplicate
   keys (case-insensitive collision) are rejected with `EVT_WEBHOOK_009`.

---

## Testing and Validation

The signature and replay logic is covered by automated tests in
`tests/webhook-signatures.test.js`. Run them with:

```bash
npm test -- tests/webhook-signatures.test.js
```

The suite covers:
-
 **valid** — a fresh timestamp and correct signature are accepted.
- **rotation** — a signature made with the previous secret is accepted.
- **invalid** — a tampered body or wrong secret is rejected with
  `EVT_WEBHOOK_001`.
- **stale** — a timestamp outside the 300s window is rejected with
  `EVT_WEBHOOK_002`.
- **duplicate** — replaying a valid event returns `EVT_WEBHOOK_003` and does not
  repeat side effects.
- **malformed** — non-JSON bodies, missing headers, and duplicate keys are
  rejected with `EVT_WEBHOOK_009`.

The tests use fixtures in `tests/fixtures/webhooks/` that include the
canonical raw body and the corresponding signature for a fixed timestamp.
