import { parseJwtRaw } from '../internal/token-parser.js';
import type { DecodedJwt, DecodeJwtOptions } from './types.js';

/**
 * Decodes a compact JSON Web Token (JWT) into its header, payload, and signature components.
 *
 * Security notice:
 * `decodeJwt` strictly inspects and decodes the token structure. It DOES NOT verify the
 * cryptographic signature or authenticate the token. Do not trust claims for authorization
 * without cryptographic verification.
 *
 * @param token The compact JWT string (header.payload.signature).
 * @param options Optional configuration such as maxTokenLength.
 * @returns The decoded header, payload, signature, and raw segments.
 * @throws {JwtParseError} When the token is malformed, has invalid segment counts, contains
 * invalid Base64URL characters or UTF-8 sequences, or contains non-object JSON values.
 */
export function decodeJwt<
  Header extends object = Record<string, unknown>,
  Payload extends object = Record<string, unknown>
>(token: string, options?: DecodeJwtOptions): DecodedJwt<Header, Payload> {
  const parsed = parseJwtRaw<Header, Payload>(token, {
    maxTokenLength: options?.maxTokenLength,
  });

  return {
    header: parsed.header,
    payload: parsed.payload,
    signature: parsed.signature,
    segments: parsed.segments,
  };
}
