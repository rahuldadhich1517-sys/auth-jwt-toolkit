import { parseJwtRaw } from '../internal/token-parser.js';
import { JwtExpiryError, ErrorCodes } from '../internal/errors.js';
import {
  isValidNumericDate,
  resolveReferenceTime,
  validateClockTolerance,
  numericDateToDate,
  numericDateToIso,
} from '../internal/time.js';
import type {
  GetJwtExpiryOptions,
  JwtExpiryResult,
  IsJwtExpiredOptions,
  GetJwtRemainingValidityOptions,
} from './types.js';

/**
 * Extracts and formats the expiration (`exp`) claim from a JWT.
 * Safely converts NumericDate values to dates, ISO strings, and calculated validity seconds.
 *
 * @param token The compact JWT string.
 * @param options Reference time and clock tolerance options.
 * @returns Structured expiration details, or null fields if no `exp` claim is present.
 * @throws {JwtParseError} When the token structure is malformed.
 * @throws {JwtExpiryError} When the `exp` claim is present but is not a valid NumericDate.
 */
export function getJwtExpiry(
  token: string,
  options: GetJwtExpiryOptions = {}
): JwtExpiryResult {
  const parsed = parseJwtRaw(token, {
    maxTokenLength: options.maxTokenLength,
  });

  const payload = parsed.payload;

  if (payload.exp === undefined) {
    return {
      hasExpiration: false,
      exp: null,
      date: null,
      iso: null,
      isExpired: null,
      remainingValiditySeconds: null,
    };
  }

  if (!isValidNumericDate(payload.exp)) {
    throw new JwtExpiryError(
      'Claim "exp" is present but is not a valid NumericDate (finite number)',
      ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM
    );
  }

  const exp = payload.exp;
  const currentTime = resolveReferenceTime(options.now);
  const tolerance = validateClockTolerance(options.clockToleranceSeconds);

  const date = numericDateToDate(exp);
  const iso = numericDateToIso(exp);
  const isExpired = currentTime >= exp + tolerance;
  const remainingValiditySeconds = Math.floor(exp - currentTime);

  return {
    hasExpiration: true,
    exp,
    date,
    iso,
    isExpired,
    remainingValiditySeconds,
  };
}

/**
 * Determines whether a JWT is expired relative to a reference time and clock tolerance.
 *
 * Security notice:
 * A missing `exp` claim is NEVER silently treated as valid forever. By default, attempting
 * to check expiration on a token without an `exp` claim throws a JwtExpiryError unless
 * explicitly configured via `options.treatMissingExpAs`.
 *
 * @param token The compact JWT string.
 * @param options Expiration checking options.
 * @returns True if expired, false if active.
 * @throws {JwtParseError} When the token is malformed.
 * @throws {JwtExpiryError} When the `exp` claim is missing (by default) or invalid.
 */
export function isJwtExpired(
  token: string,
  options: IsJwtExpiredOptions = {}
): boolean {
  const parsed = parseJwtRaw(token, {
    maxTokenLength: options.maxTokenLength,
  });

  const payload = parsed.payload;

  if (payload.exp === undefined) {
    const strategy = options.treatMissingExpAs ?? 'error';
    if (strategy === 'expired') {
      return true;
    }
    if (strategy === 'not-expired') {
      return false;
    }
    throw new JwtExpiryError(
      'Token does not contain an "exp" (expiration) claim',
      ErrorCodes.ERR_NO_EXPIRATION_CLAIM
    );
  }

  if (!isValidNumericDate(payload.exp)) {
    throw new JwtExpiryError(
      'Claim "exp" is present but is not a valid NumericDate (finite number)',
      ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM
    );
  }

  const currentTime = resolveReferenceTime(options.now);
  const tolerance = validateClockTolerance(options.clockToleranceSeconds);

  // RFC 7519 § 4.1.4: current time MUST be before the expiration date/time
  return currentTime >= payload.exp + tolerance;
}

/**
 * Calculates remaining validity of a token in seconds.
 *
 * Returns:
 * - A positive number of seconds if the token is currently valid.
 * - 0 if the token is expiring at the exact current second.
 * - A negative number of seconds if the token is already expired.
 * - `null` if the token does not contain an `exp` claim (distinguishing absence of expiration from validity).
 *
 * @param token The compact JWT string.
 * @param options Reference time options.
 * @returns Seconds remaining until expiration, or null if no `exp` claim exists.
 * @throws {JwtParseError} When the token is malformed.
 * @throws {JwtExpiryError} When the `exp` claim is present but invalid.
 */
export function getJwtRemainingValidity(
  token: string,
  options: GetJwtRemainingValidityOptions = {}
): number | null {
  const parsed = parseJwtRaw(token, {
    maxTokenLength: options.maxTokenLength,
  });

  const payload = parsed.payload;

  if (payload.exp === undefined) {
    return null;
  }

  if (!isValidNumericDate(payload.exp)) {
    throw new JwtExpiryError(
      'Claim "exp" is present but is not a valid NumericDate (finite number)',
      ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM
    );
  }

  const currentTime = resolveReferenceTime(options.now);
  return Math.floor(payload.exp - currentTime);
}
