/**
 * Configuration options for validateJwt.
 */
export interface JwtValidatorOptions {
  /**
   * List of claim names that must be present in the payload.
   */
  readonly requiredClaims?: string[];

  /**
   * If true, requires the token to contain a valid `exp` claim.
   * @default false
   */
  readonly requireExpiration?: boolean;

  /**
   * Expected issuer or allowed issuers (`iss` claim).
   */
  readonly issuer?: string | string[];

  /**
   * Expected audience or allowed audiences (`aud` claim).
   */
  readonly audience?: string | string[];

  /**
   * Clock tolerance (leeway) in seconds to account for clock skew.
   * Must be a non-negative finite number.
   * @default 0
   */
  readonly clockToleranceSeconds?: number;

  /**
   * Reference time used for date evaluations.
   * Accepts a Date instance or a numeric timestamp (seconds or milliseconds).
   * Useful for deterministic testing.
   * @default Date.now()
   */
  readonly now?: Date | number;

  /**
   * Maximum allowed token length in characters.
   * @default 65536
   */
  readonly maxTokenLength?: number;
}

/**
 * Details of a validation failure.
 */
export interface JwtValidationError {
  /**
   * Machine-readable error code.
   * Examples: 'MALFORMED_TOKEN', 'TOKEN_EXPIRED', 'TOKEN_NOT_YET_VALID',
   * 'MISSING_REQUIRED_CLAIM', 'INVALID_CLAIM_TYPE', 'ISSUER_MISMATCH', 'AUDIENCE_MISMATCH'.
   */
  readonly code: string;

  /**
   * Human-readable description of the validation failure.
   */
  readonly message: string;

  /**
   * The name of the claim associated with the error, if applicable.
   */
  readonly claim?: string;
}

/**
 * Result returned by validateJwt.
 */
export interface JwtValidationResult {
  /**
   * True only if both structure and configured claim validations passed.
   *
   * SECURITY WARNING: `valid: true` DOES NOT imply that the token signature was verified
   * or that the token is authentic. Signature verification was NOT performed.
   */
  readonly valid: boolean;

  /**
   * Indicates whether the compact JWT structure, Base64URL encoding,
   * UTF-8 sequences, and JSON headers/payloads were syntactically valid.
   */
  readonly structureValid: boolean;

  /**
   * Indicates whether all inspected claims satisfied configured validation rules.
   */
  readonly claimsValid: boolean;

  /**
   * True if the token has an `exp` claim and the current time is at or beyond the expiration boundary.
   */
  readonly expired: boolean;

  /**
   * True if the token has an `nbf` claim and the current time is before the not-before boundary.
   */
  readonly notYetValid: boolean;

  /**
   * Explicit security flag: Always false.
   * This library validates structure and claims, but never performs cryptographic signature verification.
   */
  readonly signatureVerified: false;

  /**
   * List of validation errors, if any occurred.
   */
  readonly errors: readonly JwtValidationError[];

  /**
   * Non-fatal warnings about the token (e.g. unsecured token with alg 'none', missing exp claim, future iat).
   */
  readonly warnings: readonly string[];
}
