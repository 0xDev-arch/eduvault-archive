// Issue #649: strict, nonce-based CSP.
//
// next.config.mjs previously shipped `script-src 'self' 'unsafe-inline'
// 'unsafe-eval'` unconditionally — this defeats CSP's core XSS mitigation,
// since inline/eval'd script is allowed regardless of its origin. This
// middleware generates a fresh, cryptographically random nonce per request
// and builds the CSP here instead, so `next.config.mjs`'s static headers()
// no longer need to (and must not) also set script-src, or the two would
// conflict — only one Content-Security-Policy header can win, and Next
// merges middleware-set response headers on top of next.config's, so this
// is the actual effective policy.
//
// The nonce is threaded to the app via the `x-nonce` request header (read
// in src/app/layout.js via next/headers) and applied to the one inline
// <script> in this app (the theme-init snippet) via a `nonce` prop.

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';

const WEBHOOK_MAX_SKEW_MS = 5 * 60 * 1000;
function generateNonce() {
  // 16 random bytes, base64-encoded — the standard nonce size used in
  // Next.js's own strict-CSP documentation/examples.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString('base64');
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyWebhookSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return timingSafeEqualHex(expected, signatureHeader);
}

function isStaleTimestamp(timestampHeader) {
  const ts = Number(timestampHeader);
  if (!Number.isFinite(ts)) return true;
  return Math.abs(Date.now() - ts) > WEBHOOK_MAX_SKEW_MS;
}

async function handleWebhook(request) {
  const rawBody = await request.text();
  const signature = request.headers.get('x-webhook-signature');
  const timestamp = request.headers.get('x-webhook-timestamp');
  const eventId = request.headers.get('x-webhook-id');
  const secret = process.env.WEBHOOK_SIGNING_SECRET;

  if (!eventId) {
    return NextResponse.json(
      { error: 'malformed_event', message: 'Missing x-webhook-id header' },
      { status: 400 }
    );
  }

  if (isStaleTimestamp(timestamp)) {
    return NextResponse.json(
      { error: 'stale_event', message: 'Timestamp outside allowed replay window' },
      { status: 400 }
    );
  }

  if (!verifyWebhookSignature(rawBody, signature, secret)) {
    return NextResponse.json(
      { error: 'invalid_signature', message: 'Signature verification failed' },
      { status: 401 }
    );
  }

  const { isDuplicateEvent } = await import('./src/lib/webhookReplayStore.js');
  if (await isDuplicateEvent(eventId)) {
    return NextResponse.json(
      { error: 'duplicate_event', message: 'Event already processed', eventId },
      { status: 409 }
    );
  }

  return NextResponse.json({ ok: true, eventId }, { status: 200 });
}

export function middleware(request) {
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

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  // If the user tries to access /dashboard but has no auth_token, redirect them.
  if (request.nextUrl.pathname.startsWith('/dashboard') && !request.cookies.has('auth_token')) {
    const url = request.nextUrl.clone();
    url.pathname = '/';
    return NextResponse.redirect(url);
  }

  if (request.nextUrl.pathname.startsWith('/api/webhooks/')) {
    return handleWebhook(request);
  }

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  response.headers.set('Content-Security-Policy', csp);

  return response;
}

export const config = {
  matcher: [
    // Apply to every route except static assets and Next internals, which
    // don't render the app shell / theme-init script and don't need a nonce.
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
