/**
 * Base error class for all auth-jwt-toolkit errors.
 */
export class JwtToolkitError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'JwtToolkitError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error thrown when decoding or parsing a JWT token fails due to malformed input,
 * invalid Base64URL encoding, invalid UTF-8 sequences, or invalid JSON structures.
 */
export class JwtParseError extends JwtToolkitError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = 'JwtParseError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error thrown when evaluating JWT expiration fails due to missing or invalid expiration claims,
 * or invalid reference time configurations.
 */
export class JwtExpiryError extends JwtToolkitError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = 'JwtExpiryError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error codes used throughout auth-jwt-toolkit.
 */
export const ErrorCodes = {
  ERR_INVALID_TOKEN_TYPE: 'ERR_INVALID_TOKEN_TYPE',
  ERR_TOKEN_TOO_LARGE: 'ERR_TOKEN_TOO_LARGE',
  ERR_INVALID_SEGMENT_COUNT: 'ERR_INVALID_SEGMENT_COUNT',
  ERR_EMPTY_SEGMENT: 'ERR_EMPTY_SEGMENT',
  ERR_INVALID_BASE64URL: 'ERR_INVALID_BASE64URL',
  ERR_INVALID_UTF8: 'ERR_INVALID_UTF8',
  ERR_INVALID_JSON: 'ERR_INVALID_JSON',
  ERR_INVALID_JSON_OBJECT: 'ERR_INVALID_JSON_OBJECT',
  ERR_NO_EXPIRATION_CLAIM: 'ERR_NO_EXPIRATION_CLAIM',
  ERR_INVALID_EXPIRATION_CLAIM: 'ERR_INVALID_EXPIRATION_CLAIM',
  ERR_INVALID_REFERENCE_TIME: 'ERR_INVALID_REFERENCE_TIME',
  ERR_INVALID_CLOCK_TOLERANCE: 'ERR_INVALID_CLOCK_TOLERANCE',
} as const;

export type ErrorCode = typeof ErrorCodes[keyof typeof ErrorCodes];
