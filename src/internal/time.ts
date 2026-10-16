import { JwtExpiryError, ErrorCodes } from './errors.js';

/**
 * Validates whether a value is a valid RFC 7519 NumericDate.
 * A NumericDate must be a finite, non-NaN number representing seconds since Epoch.
 * String numbers, booleans, objects, arrays, NaN, and infinities are rejected.
 */
export function isValidNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && !Number.isNaN(value);
}

/**
 * Converts a NumericDate (seconds since Epoch) to a JavaScript Date object.
 */
export function numericDateToDate(numericDate: number): Date {
  return new Date(Math.round(numericDate * 1000));
}

/**
 * Safely converts a NumericDate to an ISO 8601 string.
 * Returns null if the resulting date is invalid or out of range.
 */
export function numericDateToIso(numericDate: number): string | null {
  try {
    const d = numericDateToDate(numericDate);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  } catch {
    return null;
  }
}

/**
 * Resolves a reference time to a NumericDate (in seconds).
 * Accepts an optional Date instance or a numeric timestamp.
 * If number is > 1e11, it is treated as milliseconds (e.g. Date.now()) and converted to seconds.
 * Defaults to current system time if omitted.
 */
export function resolveReferenceTime(now?: Date | number): number {
  if (now === undefined) {
    return Math.floor(Date.now() / 1000);
  }

  if (now instanceof Date) {
    const ms = now.getTime();
    if (Number.isNaN(ms)) {
      throw new JwtExpiryError(
        'Provided reference time is an Invalid Date',
        ErrorCodes.ERR_INVALID_REFERENCE_TIME
      );
    }
    return Math.floor(ms / 1000);
  }

  if (typeof now === 'number') {
    if (!Number.isFinite(now) || Number.isNaN(now)) {
      throw new JwtExpiryError(
        'Provided reference time number must be a finite number',
        ErrorCodes.ERR_INVALID_REFERENCE_TIME
      );
    }
    // If timestamp is large (greater than 1e11), it is in milliseconds; convert to seconds
    return Math.abs(now) > 1e11 ? Math.floor(now / 1000) : now;
  }

  throw new JwtExpiryError(
    'Reference time must be a Date or number',
    ErrorCodes.ERR_INVALID_REFERENCE_TIME
  );
}

/**
 * Validates and normalizes clock tolerance in seconds.
 * Must be a non-negative finite number.
 */
export function validateClockTolerance(toleranceSeconds?: number): number {
  if (toleranceSeconds === undefined) {
    return 0;
  }

  if (
    typeof toleranceSeconds !== 'number' ||
    !Number.isFinite(toleranceSeconds) ||
    Number.isNaN(toleranceSeconds) ||
    toleranceSeconds < 0
  ) {
    throw new JwtExpiryError(
      'Clock tolerance must be a non-negative finite number of seconds',
      ErrorCodes.ERR_INVALID_CLOCK_TOLERANCE
    );
  }

  return toleranceSeconds;
}
