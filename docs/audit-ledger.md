# Tamper-Evident Audit Ledger

Privileged moderation, refund, verification, and account-status transitions append a record to the `audit_ledger` MongoDB collection. Each record contains a minimized actor identifier, an `actorProof` hash, action, target type and identifier, result, reason, intent hash, timestamp, sequence, previous hash, and record hash. Sensitive request bodies and personal fields are never copied into the ledger.

## Integrity and export

`GET /api/admin/audit-ledger` requires an admin session. It supports `action`, `actor`, `targetType`, `operationId`, `from`, `to`, and bounded `limit` filters. An unfiltered response includes verification for the complete chain. Filtered exports are for investigation and are explicitly not presented as complete-chain verification. Offline tools can verify the exported `records` with `verifyAuditRecords` from `src/lib/backend/auditLedger.js`.

The unique `operationId` makes retries exactly once. The unique sequence index causes competing writers to retry instead of silently creating a second record for the same position. Missing, edited, or reordered records fail verification. A MongoDB Deployment must restrict delete/update privileges on `audit_ledger` to the migration/retention operator and alert on any attempted mutation.

## Signed activity receipts

Critical user operations also emit a signed receipt that the actor can retain and verify independently of the ledger database. Receipts are written to the `activity_receipts` MongoDB collection and are created for these operations:

-  `storage.create` — creating a student-owned storage record.
-  `storage.update` — updating a student-owned storage record.
-  `storage.delete` — deleting a student-owned storage record.
-  `storage.share` — granting or revoking access to a storage record.
-  `marketplace.list` — listing a learning asset for sale.
-  `marketplace.purchase` — purchasing a learning asset.
-  `marketplace.refund` — refunding a marketplace order.
-  `permission.grant` — granting a permission on a record or asset.
-  `permission.revoke` — revoking a permission on a record or asset.
-  `account.status` — account-status transitions that affect a student's access.

Each receipt contains a canonical payload with the following fields:

-  `receiptId` — stable identifier derived from the canonical payload hash.
-  `operationId` — caller-supplied idempotency key; duplicate requests return the existing receipt.
-  `actor` — minimized actor identifier (user id or service id).
-  `actorProof` — SHA-256 commitment over the actor identifier and operation.
-  `action` — one of the operations listed above.
-  `timestamp` — ISO-8601 time of receipt creation.
-  `status` — one of `success`, `denied`, `failed`, or `pending`.
-  `externalRefs` — map of external references (e.g. `recordId`, `orderId`, `listingId`, `permissionId`).
-  `intentHash` — canonical hash of the request intent without sensitive body content.
-  `previousHash` — hash of the previous receipt in the actor's chain.
-  `payloadHash` — canonical SHA-256 hash of the payload fields above.
-  `signature` — Ed25519 signature over `payloadHash` using the configured signing key.
-  `keyId` — identifier of the signing key used to produce `signature`.

Payloads are canonicalized with a deterministic JSON encoding (sorted keys, no insignificant whitespace) before hashing and signing, so the same operation always produces the same `receiptId` and `payloadHash`. The `operationId` unique index makes retries exactly once; a duplicate request returns the existing receipt without creating a new one.

## Receipt lookup

`GET /api/receipts/:receiptId` returns a receipt to its actor or to an admin. The endpoint authenticates the requester, checks that the requester is the actor or holds an admin session, and returns `denied` in all other cases. The response includes the canonical payload, `payloadHash`, `signature`, `keyId`, and a `verified` boolean computed by re-hashing the payload and verifying the signature against the public key for `keyId`.

Tamper detection is explicit: if any payload field is altered, `payloadHash` no longer matches and `verified` is `false`. If the signature is altered or the wrong key is used, signature verification fails. The `activity_receipts` collection must restrict update/delete privileges to the migration/retention operator, and any attempted mutation must alert.

## Key rotation and retention

The current actor proof is a SHA-256 commitment, so it does not require a signing-key rotation. Receipt signing keys are identified by `keyId`. Store `keyId` with each record and receipt, keep retired public keys available for the full retention period, and rotate by configuration without rewriting historical records. Never replace an old key or re-sign old records.

After a key rotation, new receipts are signed with the new key and record the new `keyId`. Receipts signed with retired keys remain verifiable as long as the corresponding public key is available. The activity receipt chain is per-actor and is verified in order using `previousHash` linkage.

Retain ledger and receipt records for the organisation's legal and incident-response period, configured through the database retention policy rather than application deletion. Before expiry, export and independently verify the chain, then retain the verified export and its checkpoint digest in write-once storage. `POST /api/admin/audit-ledger `creates a verified checkpoint and posts it to the configured `AUDIT_CHECKPOINT_URL` anchor service, making a compromised database unable to rewrite history without detection.

## Rollout

Deploy the indexes before enabling privileged writes, deploy the application in append-only mode, and monitor duplicate-key and chain-conflict errors. Existing console and refund-local audit records remain available for compatibility; new privileged operations are written to the shared ledger. Backfill is intentionally excluded because historical records lack the canonical actor proof and intent fields.
