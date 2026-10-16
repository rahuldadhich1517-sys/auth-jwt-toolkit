import { describe, it, expect } from 'vitest';
import {
  getJwtExpiry,
  isJwtExpired,
  getJwtRemainingValidity,
  validateJwt,
  JwtExpiryError,
  JwtParseError,
  ErrorCodes,
} from '../src/index.js';
import { createTestToken, TEST_EPOCH } from './helpers/test-tokens.js';

describe('jwt-expiry: comprehensive test matrix', () => {
  const referenceTime = TEST_EPOCH; // 1700000000

  describe('A. getJwtExpiry()', () => {
    it('extracts valid future expiration and formats Date, ISO, and remaining validity', () => {
      const expTime = referenceTime + 3600;
      const token = createTestToken(undefined, { exp: expTime });
      const result = getJwtExpiry(token, { now: referenceTime });

      expect(result.hasExpiration).toBe(true);
      expect(result.exp).toBe(expTime);
      expect(result.date).toEqual(new Date(expTime * 1000));
      expect(result.iso).toBe('2023-11-14T23:13:20.000Z');
      expect(result.isExpired).toBe(false);
      expect(result.remainingValiditySeconds).toBe(3600);
    });

    it('extracts expired token and computes negative remaining validity', () => {
      const expTime = referenceTime - 180;
      const token = createTestToken(undefined, { exp: expTime });
      const result = getJwtExpiry(token, { now: referenceTime });

      expect(result.hasExpiration).toBe(true);
      expect(result.isExpired).toBe(true);
      expect(result.remainingValiditySeconds).toBe(-180);
      expect(result.iso).toBe('2023-11-14T22:10:20.000Z');
    });

    it('returns hasExpiration: false and null fields when exp is absent', () => {
      const token = createTestToken(undefined, { sub: 'usr_no_exp' });
      const result = getJwtExpiry(token);

      expect(result.hasExpiration).toBe(false);
      expect(result.exp).toBeNull();
      expect(result.date).toBeNull();
      expect(result.iso).toBeNull();
      expect(result.isExpired).toBeNull();
      expect(result.remainingValiditySeconds).toBeNull();
    });

    it('supports expiration at epoch zero (1970-01-01T00:00:00.000Z)', () => {
      const token = createTestToken(undefined, { exp: 0 });
      const result = getJwtExpiry(token, { now: referenceTime });

      expect(result.hasExpiration).toBe(true);
      expect(result.exp).toBe(0);
      expect(result.iso).toBe('1970-01-01T00:00:00.000Z');
      expect(result.isExpired).toBe(true);
      expect(result.remainingValiditySeconds).toBe(-referenceTime);
    });

    it('supports negative expiration dates (dates before 1970)', () => {
      const token = createTestToken(undefined, { exp: -86400 }); // 1969-12-31
      const result = getJwtExpiry(token, { now: referenceTime });

      expect(result.hasExpiration).toBe(true);
      expect(result.exp).toBe(-86400);
      expect(result.iso).toBe('1969-12-31T00:00:00.000Z');
      expect(result.isExpired).toBe(true);
    });

    it('supports fractional NumericDate values', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 0.5 });
      const result = getJwtExpiry(token, { now: referenceTime });

      expect(result.hasExpiration).toBe(true);
      expect(result.exp).toBe(referenceTime + 0.5);
      expect(result.isExpired).toBe(false);
      expect(result.date?.getUTCMilliseconds()).toBe(500);
    });

    it('throws JwtExpiryError with ERR_INVALID_EXPIRATION_CLAIM for non-numeric exp', () => {
      const invalidTokens = [
        createTestToken(undefined, { exp: '1700000000' }),
        createTestToken(undefined, { exp: true }),
        createTestToken(undefined, { exp: null }),
        createTestToken(undefined, { exp: {} }),
        createTestToken(undefined, { exp: [1700000000] }),
        createTestToken(undefined, { exp: Number.NaN }),
        createTestToken(undefined, { exp: Infinity }),
      ];

      for (const t of invalidTokens) {
        expect(() => getJwtExpiry(t)).toThrowError(JwtExpiryError);
        expect(() => getJwtExpiry(t)).toThrowError(
          expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
        );
      }
    });

    it('throws JwtParseError on malformed token strings', () => {
      expect(() => getJwtExpiry('not.a-token')).toThrowError(JwtParseError);
    });

    it('honors clockToleranceSeconds in isExpired field', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 10 });

      // Without tolerance: expired
      expect(getJwtExpiry(token, { now: referenceTime, clockToleranceSeconds: 0 }).isExpired).toBe(true);

      // With 15s tolerance: not expired
      expect(getJwtExpiry(token, { now: referenceTime, clockToleranceSeconds: 15 }).isExpired).toBe(false);
    });
  });

  describe('B. isJwtExpired()', () => {
    it('returns false for token expiring in future', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 100 });
      expect(isJwtExpired(token, { now: referenceTime })).toBe(false);
    });

    it('returns true for expired token in the past', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 1 });
      expect(isJwtExpired(token, { now: referenceTime })).toBe(true);
    });

    it('returns true at exact expiration second (now === exp)', () => {
      const token = createTestToken(undefined, { exp: referenceTime });
      expect(isJwtExpired(token, { now: referenceTime })).toBe(true);
    });

    it('throws JwtExpiryError by default when token has no exp claim', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      expect(() => isJwtExpired(token, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_NO_EXPIRATION_CLAIM })
      );
    });

    it('respects treatMissingExpAs: "expired" by returning true', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      expect(
        isJwtExpired(token, { now: referenceTime, treatMissingExpAs: 'expired' })
      ).toBe(true);
    });

    it('respects treatMissingExpAs: "not-expired" by returning false', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      expect(
        isJwtExpired(token, { now: referenceTime, treatMissingExpAs: 'not-expired' })
      ).toBe(false);
    });

    it('throws JwtExpiryError for invalid exp claim types', () => {
      const token = createTestToken(undefined, { exp: '1700000000' });
      expect(() => isJwtExpired(token, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );
    });

    it('honors clockToleranceSeconds option', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 5 });
      expect(isJwtExpired(token, { now: referenceTime, clockToleranceSeconds: 0 })).toBe(true);
      expect(isJwtExpired(token, { now: referenceTime, clockToleranceSeconds: 10 })).toBe(false);
    });

    it('accepts Date instance for now reference time', () => {
      const token = createTestToken(undefined, { exp: referenceTime });
      const beforeDate = new Date((referenceTime - 10) * 1000);
      const afterDate = new Date((referenceTime + 10) * 1000);

      expect(isJwtExpired(token, { now: beforeDate })).toBe(false);
      expect(isJwtExpired(token, { now: afterDate })).toBe(true);
    });
  });

  describe('C. getJwtRemainingValidity()', () => {
    it('returns positive remaining seconds for active tokens', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 450 });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(450);
    });

    it('returns 0 remaining seconds at the exact expiration second', () => {
      const token = createTestToken(undefined, { exp: referenceTime });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(0);
    });

    it('returns negative remaining seconds for expired tokens', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 90 });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(-90);
    });

    it('returns null when the token has no exp claim (not 0, not false)', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBeNull();
    });

    it('throws JwtExpiryError if exp is malformed', () => {
      const token = createTestToken(undefined, { exp: 'invalid' });
      expect(() => getJwtRemainingValidity(token, { now: referenceTime })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_EXPIRATION_CLAIM })
      );
    });

    it('accepts milliseconds timestamp for now (> 1e11)', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 500 });
      expect(getJwtRemainingValidity(token, { now: referenceTime * 1000 })).toBe(500);
    });
  });

  describe('D. Cross-utility consistency', () => {
    it('verifies complete consistency between isJwtExpired, getJwtExpiry, and validateJwt', () => {
      // 1. Expired token
      const expiredToken = createTestToken(undefined, { exp: referenceTime - 60 });
      expect(isJwtExpired(expiredToken, { now: referenceTime })).toBe(true);
      expect(getJwtExpiry(expiredToken, { now: referenceTime }).isExpired).toBe(true);
      expect(validateJwt(expiredToken, { now: referenceTime }).expired).toBe(true);
      expect(getJwtRemainingValidity(expiredToken, { now: referenceTime })).toBe(-60);

      // 2. Active token
      const activeToken = createTestToken(undefined, { exp: referenceTime + 60 });
      expect(isJwtExpired(activeToken, { now: referenceTime })).toBe(false);
      expect(getJwtExpiry(activeToken, { now: referenceTime }).isExpired).toBe(false);
      expect(validateJwt(activeToken, { now: referenceTime }).expired).toBe(false);
      expect(getJwtRemainingValidity(activeToken, { now: referenceTime })).toBe(60);

      // 3. Boundary token (now === exp)
      const boundaryToken = createTestToken(undefined, { exp: referenceTime });
      expect(isJwtExpired(boundaryToken, { now: referenceTime })).toBe(true);
      expect(getJwtExpiry(boundaryToken, { now: referenceTime }).isExpired).toBe(true);
      expect(validateJwt(boundaryToken, { now: referenceTime }).expired).toBe(true);
      expect(getJwtRemainingValidity(boundaryToken, { now: referenceTime })).toBe(0);
    });
  });
});
