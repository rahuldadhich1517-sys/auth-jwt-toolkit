import { isValidNumericDate, numericDateToDate, numericDateToIso } from './time.js';

/**
 * Checks whether an unknown value is a non-null, non-array object.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Checks whether an unknown value is a non-empty string.
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Normalizes an audience claim (which can be a string or an array of strings per RFC 7519).
 * Returns string[] if valid, or null if malformed/unsupported.
 */
export function normalizeAudience(aud: unknown): string[] | null {
  if (typeof aud === 'string') {
    return [aud];
  }
  if (Array.isArray(aud) && aud.every((item) => typeof item === 'string')) {
    return aud;
  }
  return null;
}

/**
 * Representation of a timestamp claim with parsed representations.
 */
export interface TimestampClaimDetail {
  readonly raw: number;
  readonly date: Date;
  readonly iso: string;
}

/**
 * Safely extracts and formats a NumericDate claim (such as exp, nbf, or iat).
 * Returns null if the claim is undefined or not a valid NumericDate.
 */
export function extractTimestampClaim(value: unknown): TimestampClaimDetail | null {
  if (!isValidNumericDate(value)) {
    return null;
  }

  const date = numericDateToDate(value);
  const iso = numericDateToIso(value);

  if (!iso) {
    return null;
  }

  return {
    raw: value,
    date,
    iso,
  };
}
