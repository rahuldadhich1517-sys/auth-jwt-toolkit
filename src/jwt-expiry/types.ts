/**
 * Options for getJwtExpiry.
 */
export interface GetJwtExpiryOptions {
  /**
   * Reference time for evaluating expiration.
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
 * Result returned by getJwtExpiry.
 */
export interface JwtExpiryResult {
  /**
   * True if the token contains a valid `exp` claim.
   */
  readonly hasExpiration: boolean;

  /**
   * Raw NumericDate value (seconds since Epoch), or null if not present.
   */
  readonly exp: number | null;

  /**
   * Date representation of the expiration time, or null if not present.
   */
  readonly date: Date | null;

  /**
   * ISO 8601 string representation of the expiration date, or null if not present.
   */
  readonly iso: string | null;

  /**
   * True if expired, false if not expired, or null if no `exp` claim was present.
   */
  readonly isExpired: boolean | null;

  /**
   * Remaining seconds until expiration (negative if already expired, null if no `exp` claim).
   */
  readonly remainingValiditySeconds: number | null;
}

/**
 * Options for isJwtExpired.
 */
export interface IsJwtExpiredOptions {
  /**
   * Reference time for evaluating expiration.
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

  /**
   * Behavior when the token does not contain an `exp` claim.
   * - 'error' (default): Throws a JwtExpiryError with code ERR_NO_EXPIRATION_CLAIM.
   * - 'expired': Returns true.
   * - 'not-expired': Returns false.
   * @default 'error'
   */
  readonly treatMissingExpAs?: 'error' | 'expired' | 'not-expired';
}

/**
 * Options for getJwtRemainingValidity.
 */
export interface GetJwtRemainingValidityOptions {
  /**
   * Reference time for evaluating remaining validity.
   * @default Date.now()
   */
  readonly now?: Date | number;

  /**
   * Maximum allowed token length in characters.
   * @default 65536
   */
  readonly maxTokenLength?: number;
}
