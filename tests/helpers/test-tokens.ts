import { base64UrlEncode } from '../../src/internal/base64url.js';

export const TEST_EPOCH = 1700000000; // 2023-11-14T22:13:20.000Z
export const DEFAULT_MOCK_SIGNATURE = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

/**
 * Creates a synthetic compact JWT token for testing.
 * No cryptographic signatures are created because the toolkit does not verify signatures.
 */
export function createTestToken(
  header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' },
  payload: Record<string, unknown> = { sub: '1234567890', name: 'John Doe', iat: 1516239022 },
  signature: string = DEFAULT_MOCK_SIGNATURE
): string {
  const encHeader = base64UrlEncode(JSON.stringify(header));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  return `${encHeader}.${encPayload}.${signature}`;
}

/**
 * Creates an unsecured token with alg: "none" and an empty signature segment (e.g. `header.payload.`).
 */
export function createUnsecuredToken(
  payload: Record<string, unknown> = { sub: '1234567890', name: 'John Doe' }
): string {
  const encHeader = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  return `${encHeader}.${encPayload}.`;
}

/**
 * Combines raw string segments directly into a token.
 */
export function createRawToken(
  rawHeader: string,
  rawPayload: string,
  rawSignature: string = DEFAULT_MOCK_SIGNATURE
): string {
  return `${rawHeader}.${rawPayload}.${rawSignature}`;
}

/**
 * Convenience helper to create a token with custom payload claims and an optional custom header.
 */
export function createTokenWithClaims(
  claims: Record<string, unknown>,
  header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' },
  signature: string = DEFAULT_MOCK_SIGNATURE
): string {
  return createTestToken(header, claims, signature);
}

/**
 * Encodes string to Base64URL without padding.
 */
export function encodeBase64UrlUnpadded(input: string | Uint8Array): string {
  return base64UrlEncode(input);
}
