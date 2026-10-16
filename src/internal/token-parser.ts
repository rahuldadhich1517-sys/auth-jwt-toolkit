import { JwtParseError, ErrorCodes } from './errors.js';
import { base64UrlDecode, isValidBase64Url } from './base64url.js';
import { isPlainObject } from './claims.js';

/**
 * Options for internal token parsing.
 */
export interface TokenParserOptions {
  /**
   * Maximum allowed token length in characters.
   * Helps guard against denial of service via extremely large tokens.
   * @default 65536 (64 KB)
   */
  readonly maxTokenLength?: number;
}

/**
 * The internal structured representation of a decoded JWT.
 */
export interface ParsedJwt<
  Header extends object = Record<string, unknown>,
  Payload extends object = Record<string, unknown>
> {
  readonly header: Header;
  readonly payload: Payload;
  readonly signature: string;
  readonly segments: {
    readonly header: string;
    readonly payload: string;
    readonly signature: string;
  };
}

const DEFAULT_MAX_TOKEN_LENGTH = 64 * 1024; // 64 KB

/**
 * Single, unified token parser used across all utilities.
 * Validates compact format, Base64URL segments, UTF-8 validity, and JSON structure.
 * Never executes token content and never exposes token content in error messages.
 */
export function parseJwtRaw<
  Header extends object = Record<string, unknown>,
  Payload extends object = Record<string, unknown>
>(token: unknown, options?: TokenParserOptions): ParsedJwt<Header, Payload> {
  if (typeof token !== 'string') {
    throw new JwtParseError(
      'JWT token must be a string',
      ErrorCodes.ERR_INVALID_TOKEN_TYPE
    );
  }

  if (token.length === 0) {
    throw new JwtParseError(
      'JWT token cannot be empty',
      ErrorCodes.ERR_INVALID_TOKEN_TYPE
    );
  }

  const maxLength = options?.maxTokenLength ?? DEFAULT_MAX_TOKEN_LENGTH;
  if (token.length > maxLength) {
    throw new JwtParseError(
      `JWT token exceeds maximum allowed length of ${maxLength} characters`,
      ErrorCodes.ERR_TOKEN_TOO_LARGE
    );
  }

  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new JwtParseError(
      `JWT must contain exactly 3 dot-separated segments, received ${segments.length}`,
      ErrorCodes.ERR_INVALID_SEGMENT_COUNT
    );
  }

  const [rawHeader, rawPayload, rawSignature] = segments as [string, string, string];

  if (rawHeader.length === 0) {
    throw new JwtParseError(
      'JWT header segment cannot be empty',
      ErrorCodes.ERR_EMPTY_SEGMENT
    );
  }

  if (rawPayload.length === 0) {
    throw new JwtParseError(
      'JWT payload segment cannot be empty',
      ErrorCodes.ERR_EMPTY_SEGMENT
    );
  }

  // Signature segment can be empty for unsecured tokens (e.g. alg: "none"),
  // but if present, must consist of valid Base64URL characters.
  if (rawSignature.length > 0 && !isValidBase64Url(rawSignature)) {
    throw new JwtParseError(
      'JWT signature segment contains invalid Base64URL characters',
      ErrorCodes.ERR_INVALID_BASE64URL
    );
  }

  // Decode header
  const headerJson = base64UrlDecode(rawHeader);
  let parsedHeader: unknown;
  try {
    parsedHeader = JSON.parse(headerJson);
  } catch {
    throw new JwtParseError(
      'JWT header segment contains invalid JSON',
      ErrorCodes.ERR_INVALID_JSON
    );
  }

  if (!isPlainObject(parsedHeader)) {
    throw new JwtParseError(
      'JWT header must be a JSON object',
      ErrorCodes.ERR_INVALID_JSON_OBJECT
    );
  }

  // Decode payload
  const payloadJson = base64UrlDecode(rawPayload);
  let parsedPayload: unknown;
  try {
    parsedPayload = JSON.parse(payloadJson);
  } catch {
    throw new JwtParseError(
      'JWT payload segment contains invalid JSON',
      ErrorCodes.ERR_INVALID_JSON
    );
  }

  if (!isPlainObject(parsedPayload)) {
    throw new JwtParseError(
      'JWT payload must be a JSON object',
      ErrorCodes.ERR_INVALID_JSON_OBJECT
    );
  }

  return {
    header: parsedHeader as Header,
    payload: parsedPayload as Payload,
    signature: rawSignature,
    segments: {
      header: rawHeader,
      payload: rawPayload,
      signature: rawSignature,
    },
  };
}
