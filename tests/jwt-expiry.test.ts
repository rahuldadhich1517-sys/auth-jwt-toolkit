import { describe, it, expect } from 'vitest';
import {
  getJwtExpiry,
  isJwtExpired,
  getJwtRemainingValidity,
  JwtExpiryError,
  JwtParseError,
  ErrorCodes,
} from '../src/index.js';
import { createTestToken } from './helpers/test-tokens.js';

describe('jwt-expiry: expiry utilities', () => {
  const referenceTime = 1700000000; // 2023-11-14T22:13:20.000Z

  describe('getJwtExpiry', () => {
    it('should extract valid expiration and calculate timestamps and remaining validity', () => {
      const expTime = referenceTime + 600; // 10 minutes ahead
      const token = createTestToken(undefined, { exp: expTime });

      const result = getJwtExpiry(token, { now: referenceTime });

      expect(result.hasExpiration).toBe(true);
      expect(result.exp).toBe(expTime);
      expect(result.date?.getTime()).toBe(expTime * 1000);
      expect(result.iso).toBe('2023-11-14T22:23:20.000Z');
      expect(result.isExpired).toBe(false);
      expect(result.remainingValiditySeconds).toBe(600);
    });

    it('should report hasExpiration: false and null values when exp is absent', () => {
      const token = createTestToken(undefined, { sub: 'usr_no_exp' });

      const result = getJwtExpiry(token);

      expect(result.hasExpiration).toBe(false);
      expect(result.exp).toBeNull();
      expect(result.date).toBeNull();
      expect(result.iso).toBeNull();
      expect(result.isExpired).toBeNull();
      expect(result.remainingValiditySeconds).toBeNull();
    });

    it('should throw JwtExpiryError with ERR_INVALID_EXPIRATION_CLAIM if exp is not a valid NumericDate', () => {
      const token = createTestToken(undefined, { exp: 'invalid-string' });

      expect(() => getJwtExpiry(token)).toThrowError(JwtExpiryError);
      expect(() => getJwtExpiry(token)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );
    });

    it('should throw JwtParseError on malformed token input', () => {
      expect(() => getJwtExpiry('invalid.jwt')).toThrowError(JwtParseError);
    });
  });

  describe('isJwtExpired', () => {
    it('should return false for an active token with future exp', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 100 });
      expect(isJwtExpired(token, { now: referenceTime })).toBe(false);
    });

    it('should return true for an already-expired token', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 100 });
      expect(isJwtExpired(token, { now: referenceTime })).toBe(true);
    });

    it('should return true at the exact expiration second (currentTime === exp) per RFC 7519', () => {
      // RFC 7519: current time must be BEFORE expiration date/time
      const token = createTestToken(undefined, { exp: referenceTime });
      expect(isJwtExpired(token, { now: referenceTime })).toBe(true);
    });

    it('should throw JwtExpiryError by default when token has no exp claim', () => {
      const token = createTestToken(undefined, { sub: 'usr_123' });

      expect(() => isJwtExpired(token, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_NO_EXPIRATION_CLAIM })
      );
    });

    it('should respect treatMissingExpAs option when configured', () => {
      const token = createTestToken(undefined, { sub: 'usr_123' });

      expect(
        isJwtExpired(token, { now: referenceTime, treatMissingExpAs: 'expired' })
      ).toBe(true);

      expect(
        isJwtExpired(token, { now: referenceTime, treatMissingExpAs: 'not-expired' })
      ).toBe(false);
    });

    it('should reject invalid exp types (string, boolean, array, object) with JwtExpiryError', () => {
      const stringToken = createTestToken(undefined, { exp: '1700000000' });
      expect(() => isJwtExpired(stringToken, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );

      const boolToken = createTestToken(undefined, { exp: true });
      expect(() => isJwtExpired(boolToken, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );

      const nanToken = createTestToken(undefined, { exp: Number.NaN });
      expect(() => isJwtExpired(nanToken, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );
    });

    it('should support clockToleranceSeconds in expiration calculation', () => {
      // Expired 5 seconds ago
      const token = createTestToken(undefined, { exp: referenceTime - 5 });

      // Expired without tolerance
      expect(isJwtExpired(token, { now: referenceTime, clockToleranceSeconds: 0 })).toBe(true);

      // Still valid with 10 seconds tolerance
      expect(isJwtExpired(token, { now: referenceTime, clockToleranceSeconds: 10 })).toBe(false);
    });

    it('should accept Date instance for now reference time', () => {
      const token = createTestToken(undefined, { exp: 1700000000 });
      const refDate = new Date('2023-11-14T20:00:00.000Z'); // before 1700000000

      expect(isJwtExpired(token, { now: refDate })).toBe(false);
    });

    it('should throw JwtParseError on malformed token input', () => {
      expect(() => isJwtExpired('not-a-token')).toThrowError(JwtParseError);
    });
  });

  describe('getJwtRemainingValidity', () => {
    it('should return positive seconds for an active token', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 300 });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(300);
    });

    it('should return 0 when token is expiring at the current instant', () => {
      const token = createTestToken(undefined, { exp: referenceTime });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(0);
    });

    it('should return negative seconds for an expired token', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 45 });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(-45);
    });

    it('should return null when the token has no exp claim', () => {
      const token = createTestToken(undefined, { sub: 'usr_no_exp' });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBeNull();
    });

    it('should throw JwtExpiryError if exp is malformed', () => {
      const token = createTestToken(undefined, { exp: 'not_numeric' });
      expect(() => getJwtRemainingValidity(token, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );
    });

    it('should throw JwtParseError on malformed token input', () => {
      expect(() => getJwtRemainingValidity('')).toThrowError(JwtParseError);
    });
  });
});
