import type { TimestampClaimDetail } from '../internal/claims.js';

/**
 * Options for inspectJwt.
 */
export interface JwtInspectorOptions {
  /**
   * Reference time for evaluating expiration and validity status.
   * Accepts a Date instance or a numeric timestamp (seconds or milliseconds).
   * @default Date.now()
   */
  readonly now?: Date | number;

  /**
   * Clock tolerance in seconds.
   * @default 0
   */
  readonly clockToleranceSeconds?: number;

  /**
   * Maximum allowed token length in characters.
   * @default 65536
   */
  readonly maxTokenLength?: number;
}

/**
 * Standard header fields extracted during inspection.
 */
export interface JwtHeaderSummary {
  readonly alg?: string;
  readonly typ?: string;
  readonly kid?: string;
  readonly [key: string]: unknown;
}

/**
 * Standard registered payload claims extracted during inspection.
 */
export interface JwtStandardClaims {
  readonly alg?: string;
  readonly typ?: string;
  readonly kid?: string;
  readonly iss?: string;
  readonly sub?: string;
  readonly aud?: string | readonly string[];
  readonly jti?: string;
  readonly exp: TimestampClaimDetail | null;
  readonly nbf: TimestampClaimDetail | null;
  readonly iat: TimestampClaimDetail | null;
}

/**
 * Token validity assessment based on current time and tolerance.
 */
export interface JwtValiditySummary {
  /**
   * True if an `exp` claim is present in the token.
   */
  readonly hasExpiration: boolean;

  /**
   * True if expired, false if not expired, or null if no `exp` claim is present.
   */
  readonly isExpired: boolean | null;

  /**
   * True if not yet valid (`nbf` in the future), false if valid, or null if no `nbf` claim.
   */
  readonly isNotYetValid: boolean | null;

  /**
   * Remaining seconds until expiration (negative if expired, null if no `exp` claim).
   */
  readonly remainingValiditySeconds: number | null;

  /**
   * Reference timestamp in seconds used for evaluating validity.
   */
  readonly referenceTimeSeconds: number;
}

/**
 * Unverified signature information extracted from the token.
 */
export interface JwtSignatureInfo {
  /**
   * The raw, opaque Base64URL signature segment.
   */
  readonly segment: string;

  /**
   * True if a signature segment is present (non-empty).
   */
  readonly present: boolean;

  /**
   * Explicit security flag: Always false.
   * The presence of a signature segment does NOT mean the signature has been verified.
   */
  readonly verified: false;
}

/**
 * Comprehensive inspection report returned by inspectJwt.
 */
export interface JwtInspectionResult<
  Header extends object = Record<string, unknown>,
  Payload extends object = Record<string, unknown>
> {
  /**
   * The full decoded header.
   */
  readonly header: Header;

  /**
   * The full decoded payload.
   */
  readonly payload: Payload;

  /**
   * Unverified signature details.
   */
  readonly signature: JwtSignatureInfo;

  /**
   * Extracted standard registered claims.
   */
  readonly claims: JwtStandardClaims;

  /**
   * Validity calculation based on standard time claims.
   */
  readonly validity: JwtValiditySummary;

  /**
   * Explicit security flag: Always false.
   */
  readonly signatureVerified: false;

  /**
   * Any warnings regarding malformed claim types, alg: 'none', or expired status.
   */
  readonly warnings: readonly string[];
}
