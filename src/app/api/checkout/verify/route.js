export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { getUserFromCookie } from '@/lib/api/auth';
import { verifyWalletAddressMatch } from '@/lib/stellar/checkoutService';
import { normalizeWalletAddress } from '@/lib/canonicalization';
import logger from '@/lib/logger';

/**
 * POST /api/checkout/verify
 *
 * Verifies that the wallet address in the signed transaction payload matches
 * the address stored in the user's JWT session.  Blocks submission and
 * returns a 403 if the addresses differ, defending against address-spoofing.
 *
 * Both the session address and the payload address are normalized to the
 * canonical Stellar G-address form before comparison, so equivalent input
 * (casing, whitespace, prefix variants) cannot produce inconsistent results.
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

    const sessionAddressRaw = user.walletAddress || user.address || user.publicKey || '';

    if (!sessionAddressRaw) {
      logger.warn({ userId: user.id }, 'Checkout verify: session has no wallet address');
      return NextResponse.json({ error: 'Session wallet address not found' }, { status: 400 });
    }

    // Normalize both addresses to the canonical Stellar G-address form.
    // Non-canonical input is either normalized (casing, whitespace, prefix)
    // or rejected consistently with a 400.
    const sessionAddress = normalizeWalletAddress(sessionAddressRaw);
    const normalizedPayloadAddress = normalizeWalletAddress(payloadAddress);

    if (!sessionAddress) {
      logger.warn({ userId: user.id }, 'Checkout verify: session wallet address is not canonical');
      return NextResponse.json({ error: 'Session wallet address is not canonical' }, { status: 400 });
    }

    if (!normalizedPayloadAddress) {
      logger.warn(
        { userId: user.id, payloadAddress },
        'Checkout verify: payload wallet address is not canonical'
      );
      return NextResponse.json({ error: 'payloadAddress is not a canonical Stellar address' }, { status: 400 });
    }

    // Mutable session state (warnings counter) stored on the user object.
    // In production this would be persisted via Redis / signed cookie update.
    const sessionState = user.sessionState ?? {};
    const result = verifyWalletAddressMatch({
      sessionAddress,
      payloadAddress: normalizedPayloadAddress,
      sessionState,
    });

    if (!result.valid) {
      logger.warn(
        { sessionAddress, payloadAddress: normalizedPayloadAddress, warnings: result.warnings, clearSession: result.clearSession },
        'Checkout verify: wallet address mismatch blocked submission'
      );

      if (result.clearSession) {
        return NextResponse.json(
          {
            error: 'Wallet address mismatch — session cleared due to repeated violations',
            clearSession: true,
          },
          { status: 403 }
        );
      }

      return NextResponse.json(
        {
          error: 'Wallet address in signed payload does not match session wallet',
          reason: result.reason,
          warnings: result.warnings,
        },
        { status: 403 }
      );
    }

    return NextResponse.json({ valid: true, address: sessionAddress }, { status: 200 });
  } catch (err) {
    logger.error({ err: err.message }, 'POST /api/checkout/verify error');
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}
