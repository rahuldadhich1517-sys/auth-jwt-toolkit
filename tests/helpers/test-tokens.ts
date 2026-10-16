import { base64UrlEncode } from '../../src/internal/base64url.js';

/**
 * Creates a synthetic compact JWT token for testing.
 * No cryptographic signatures are created because the toolkit does not verify signatures.
 */
export function createTestToken(
  header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' },
  payload: Record<string, unknown> = { sub: '1234567890', name: 'John Doe', iat: 1516239022 },
  signature = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
): string {
  const encHeader = base64UrlEncode(JSON.stringify(header));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  return `${encHeader}.${encPayload}.${signature}`;
}

/**
 * Creates an unsecured token with alg: "none" and an empty signature segment.
 */
export function createUnsecuredToken(
  payload: Record<string, unknown> = { sub: '1234567890', name: 'John Doe' }
): string {
  const encHeader = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  return `${encHeader}.${encPayload}.`;
}
