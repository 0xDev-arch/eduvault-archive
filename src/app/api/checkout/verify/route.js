export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { getUserFromCookie } from '@/lib/api/auth';
import { verifyWalletAddressMatch } from '@/lib/stellar/checkoutService';
import { createReceipt } from '@/lib/receipts/receiptService';
import logger from '@/lib/logger';

// NOTE: The checkout receipt UI lives in components/modals/CheckoutReceiptModal.jsx.
// That file is JSX and must be transpiled by the Next.js/SWC pipeline; it is not
// valid input for `node --check`. Syntax validation for .jsx files should run
// through the project's Jest/Babel or `next lint` tooling instead.

/**
 * POST /api/checkout/verify
 *
 * Verifies that the wallet address in the signed transaction payload matches
 * the address stored in the user's JWT session.  Blocks submission and
 * returns a 403 if the addresses differ, defending against address-spoofing.
 *
 * Body:
 *   { payloadAddress: string }   — Stellar G-address extracted from the signed payload
 *
 * Session state persists per-user in the JWT; repeated mismatches clear the session.
 */
export async function POST(req) {
  try {
    const user = await getUserFromCookie(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    const { payloadAddress } = body;

    if (!payloadAddress || typeof payloadAddress !== 'string') {
      return NextResponse.json({ error: 'Missing payloadAddress in request body' }, { status: 400 });
    }

    const sessionAddress = user.walletAddress || user.address || user.publicKey || '';

    if (!sessionAddress) {
      logger.warn({ userId: user.id }, 'Checkout verify: session has no wallet address');
      return NextResponse.json({ error: 'Session wallet address not found' }, { status: 400 });
    }

    // Mutable session state (warnings counter) stored on the user object.
    // In production this would be persisted via Redis / signed cookie update.
    const sessionState = user.sessionState ?? {};
    const result = verifyWalletAddressMatch({ sessionAddress, payloadAddress, sessionState });

    const actor = user.sub || user.id || sessionAddress;
    const idempotencyKey = `${actor}:${payloadAddress}:${result.valid ? 'valid' : 'tampered'}`;

    if (!result.valid) {
      logger.warn(
        { sessionAddress, payloadAddress, warnings: result.warnings, clearSession: result.clearSession },
        'Checkout verify: wallet address mismatch blocked submission'
      );

      const { receipt } = await createReceipt({
        operation: 'checkout.verify',
        actor: actor,
        status: 'denied',
        summary: 'Wallet address in signed payload did not match the session wallet',
        references: { sessionAddress, payloadAddress },
        metadata: { reason: result.reason, warnings: result.warnings, clearSession: Boolean(result.clearSession) },
        idempotencyKey,
      });

      if (result.clearSession) {
        return NextResponse.json(
          {
            error: 'Wallet address mismatch — session cleared due to repeated violations',
            clearSession: true,
            receiptId: receipt._id,
          },
          { status: 403 }
        );
      }

      return NextResponse.json(
        {
          error: 'Wallet address in signed payload does not match session wallet',
          reason: result.reason,
          warnings: result.warnings,
          receiptId: receipt._id,
        },
        { status: 403 }
      );
    }

    const { receipt } = await createReceipt({
      operation: 'checkout.verify',
      actor,
      status: 'verified',
      summary: 'Wallet address in signed payload matched the session wallet',
      references: { sessionAddress, payloadAddress },
      metadata: { warnings: result.warnings },
      idempotencyKey,
    });

    return NextResponse.json(
      { valid: true, address: sessionAddress, receiptId: receipt._id },
      { status: 200 }
    );
  } catch (err) {
    logger.error({ err: err.message }, 'POST /api/checkout/verify error');
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}
