# Trust controls

Material deletion/restoration checks persisted `users.securityReviewRequired`,
`materials.fraudHold` and quarantined status before mutation. Review bindings include
actor, target, operation and material search version; a changed target needs a new
review. No request-supplied risk flags are trusted. Other mutation routes are not
covered by this initial integration.

`GET /api/admin/fraud-reviews` lists up to 100 pending reviews for active admins.
`POST` accepts `{id, decision: "approved" | "rejected", reason}`. Self-review is
forbidden. Resolution and attributed history are one atomic Mongo update; duplicate
decisions return 409. Review evidence stores only enumerated signals and material
status, never storage keys, files, cookies or request bodies. Only admins can read
the evidence. Approval authorizes retry through normal ownership/session checks;
it does not execute the action or bypass other gates.
Pass `?id=...` to GET to read a resolved review and its complete audit history.
The endpoint limits requests to 60/minute.

No backfill is required. Mongo creates `fraud_reviews` on first use; its built-in
unique `_id` deduplicates identical requests. Grant application-only writes and
restrict database operator access. Embedded audit arrays are intended for bounded
review histories, not an external immutable archive.

Validation: `node --test tests/backend/fraud-review.test.mjs`.

## Consent

`GET /api/consent?policy=catalog-management:1` returns published policy text, its
SHA-256 version hash and the caller's own history. `POST /api/consent` accepts
`{policyKey, versionHash, decision: "accepted" | "revoked"}`. Actor, source and time
are server-assigned. History cannot be requested for another account. Responses
are no-store. Consent events append atomically with the current decision using
revision compare-and-swap; conflicting submissions return 409 and may be retried.

Material deletion/restoration returns 428 with the exact required policy if consent
is missing, revoked or stale. Consent does not replace ownership or maintainer
authorization. To change terms, add a new immutable entry to `POLICIES`, retain
old entries for disputes, and update `REQUIRED_CONSENT`. Deploying that change
requires renewed consent; existing records are never silently upgraded. Review
the supplied catalog policy wording before production deployment. There is no
backfill or grandfathering. The new `consent_ledgers` collection uses Mongo's
unique `_id`; histories are embedded and should be monitored against Mongo's
document size limit. Validate with `node --test tests/backend/consent-ledger.test.mjs`.

## Support timelines

`POST /api/support/cases` with `{summary}` creates a case owned by the active caller.
With `{id, type, content, visibility}` it appends an event. Types are status, note,
evidence, escalation and resolution; visibility is user (default) or private.
Only admins may add private events or types other than note. Evidence should be
redacted references; never paste tokens, raw student records or storage credentials.
`GET /api/support/cases?id=...` allows only the owner or an active admin. Owner
responses omit private events and their hashes/sequence numbers. Resolved cases
reject further writes. Status is a narrative update; escalation and resolution
set lifecycle state explicitly.

`support_cases` embeds a SHA-256 chain with actor, time and strictly increasing
sequence. Each append atomically compares revision and head, stores the new event
and updates state. Concurrent appends return 409 for retry. Reads and appends
verify integrity and fail closed on corruption. This detects accidental edits,
reordering and truncation against the stored head; a database administrator able
to rewrite the whole chain can forge it. External head anchoring is deferred.
No migration/configuration is needed; enforce application-only writes, backups
and monitor document growth. Validate with
`node --test tests/backend/support-timeline.test.mjs`.
