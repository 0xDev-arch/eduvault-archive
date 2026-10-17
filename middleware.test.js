import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { middleware } from './middleware';
import {
  verifyWebhookSignature,
  processWebhookEvent,
  resetWebhookReplayStore,
} from './webhook-verification';

function makeRequest(url = 'http://localhost:3000/marketplace') {
  return new NextRequest(url);
}

describe('middleware — nonce-based CSP (issue #649)', () => {
  it('sets a Content-Security-Policy header with a nonce-based script-src', () => {
    const response = middleware(makeRequest());
    const csp = response.headers.get('Content-Security-Policy');

    expect(csp).toBeTruthy();
    expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
  });

  it('never allows unsafe-inline or unsafe-eval in script-src', () => {
    const response = middleware(makeRequest());
    const csp = response.headers.get('Content-Security-Policy');
    const scriptSrcDirective = csp.split(';').find((d) => d.trim().startsWith('script-src'));

    expect(scriptSrcDirective).not.toContain('unsafe-inline');
    expect(scriptSrcDirective).not.toContain('unsafe-eval');
  });

  it('generates a different nonce on every request', () => {
    const csp1 = middleware(makeRequest()).headers.get('Content-Security-Policy');
    const csp2 = middleware(makeRequest()).headers.get('Content-Security-Policy');

    const nonce1 = csp1.match(/'nonce-([A-Za-z0-9+/=]+)'/)[1];
    const nonce2 = csp2.match(/'nonce-([A-Za-z0-9+/=]+)'/)[1];

    expect(nonce1).not.toBe(nonce2);
  });

  it('threads the same nonce through the x-nonce request header used by layout.js', () => {
    const response = middleware(makeRequest());
    const csp = response.headers.get('Content-Security-Policy');
    const nonceInCsp = csp.match(/'nonce-([A-Za-z0-9+/=]+)'/)[1];
    const nonceHeader = response.headers.get('x-middleware-request-x-nonce');

    expect(nonceHeader).toBe(nonceInCsp);
  });

  it('sets object-src none and frame-ancestors none', () => {
    const response = middleware(makeRequest());
    const csp = response.headers.get('Content-Security-Policy');

    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it('includes a report-uri pointing at the CSP report endpoint', () => {
    const response = middleware(makeRequest());
    const csp = response.headers.get('Content-Security-Policy');

    expect(csp).toContain('report-uri /api/csp-report');
  });
});

describe('webhook verification — signed events and replay window', () => {
  const SECRET = 'test-webhook-secret';
  const NOW = 1_700_000_000_000;
  const WINDOW_MS = 5 * 60 * 1000;

  function sign(payload, timestamp, secret = SECRET) {
    const { createHmac } = require('node:crypto');
    return createHmac('sha256', secret)
      .update(`${timestamp}.${payload}`)
      .digest('hex');
  }

  function makeEvent(overrides = {}) {
    const payload = JSON.stringify({ id: 'evt_1', type: 'marketplace.purchase', data: {} });
    const timestamp = NOW;
    return {
      payload,
      timestamp,
      signature: sign(payload, timestamp),
      ...overrides,
    };
  }

  beforeEach(() => {
    resetWebhookReplayStore();
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  it('accepts a valid signed event within the replay window', () => {
    const event = makeEvent();
    const result = verifyWebhookSignature(event, { secret: SECRET, windowMs: WINDOW_MS });

    expect(result.ok).toBe(true);
  });

  it('rejects an invalid signature with a structured error', () => {
    const event = makeEvent({ signature: 'deadbeef' });
    const result = verifyWebhookSignature(event, { secret: SECRET, windowMs: WINDOW_MS });

    expect(result.ok).toBe(false);
    expect(result.error).toMatchObject({ code: 'INVALID_SIGNATURE', status: 401 });
  });

  it('rejects a stale timestamp outside the replay window', () => {
    const staleTimestamp = NOW - WINDOW_MS - 1;
    const payload = JSON.stringify({ id: 'evt_stale', type: 'marketplace.purchase', data: {} });
    const event = {
      payload,
      timestamp: staleTimestamp,
      signature: sign(payload, staleTimestamp),
    };

    const result = verifyWebhookSignature(event, { secret: SECRET, windowMs: WINDOW_MS });

    expect(result.ok).toBe(false);
    expect(result.error).toMatchObject({ code: 'STALE_TIMESTAMP', status: 400 });
  });

  it('rejects a future timestamp outside the replay window', () => {
    const futureTimestamp = NOW + WINDOW_MS + 1;
    const payload = JSON.stringify({ id: 'evt_future', type: 'marketplace.purchase', data: {} });
    const event = {
      payload,
      timestamp: futureTimestamp,
      signature: sign(payload, futureTimestamp),
    };

    const result = verifyWebhookSignature(event, { secret: SECRET, windowMs: WINDOW_MS });

    expect(result.ok).toBe(false);
    expect(result.error).toMatchObject({ code: 'STALE_TIMESTAMP', status: 400 });
  });

  it('rejects malformed events with a structured error', () => {
    const result = verifyWebhookSignature(
      { payload: null, timestamp: 'not-a-number', signature: undefined },
      { secret: SECRET, windowMs: WINDOW_MS }
    );

    expect(result.ok).toBe(false);
    expect(result.error).toMatchObject({ code: 'MALFORMED_EVENT', status: 400 });
  });

  it('does not repeat side effects for duplicate valid events', () => {
    const event = makeEvent();
    const sideEffect = vi.fn();

    const first = processWebhookEvent(event, { secret: SECRET, windowMs: WINDOW_MS }, sideEffect);
    const second = processWebhookEvent(event, { secret: SECRET, windowMs: WINDOW_MS }, sideEffect);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    expect(second.error).toMatchObject({ code: 'DUPLICATE_EVENT', status: 409 });
    expect(sideEffect).toHaveBeenCalledTimes(1);
  });
});
