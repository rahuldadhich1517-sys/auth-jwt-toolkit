import { describe, it, expect } from 'vitest';
import { validateJwt } from '../src/index.js';
import { createTestToken } from './helpers/test-tokens.js';

describe('jwt-validator: validateJwt', () => {
  const referenceTime = 1700000000; // 2023-11-14T22:13:20.000Z

  it('should return valid: true for correctly structured token satisfying all defaults', () => {
    const token = createTestToken(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'usr_123', exp: referenceTime + 3600, iat: referenceTime - 100 }
    );

    const result = validateJwt(token, { now: referenceTime });

    expect(result.valid).toBe(true);
    expect(result.structureValid).toBe(true);
    expect(result.claimsValid).toBe(true);
    expect(result.expired).toBe(false);
    expect(result.notYetValid).toBe(false);
    expect(result.signatureVerified).toBe(false);
    expect(result.errors).toHaveLength(0);
  });

  it('should explicitly guarantee signatureVerified is false even when valid is true', () => {
    const token = createTestToken();
    const result = validateJwt(token, { now: referenceTime });
    expect(result.signatureVerified).toBe(false);
  });

  it('should fail with MISSING_REQUIRED_CLAIM when a required claim is missing', () => {
    const token = createTestToken(undefined, { sub: 'usr_123' });
    const result = validateJwt(token, {
      requiredClaims: ['sub', 'tenant_id'],
      now: referenceTime,
    });

    expect(result.valid).toBe(false);
    expect(result.claimsValid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'MISSING_REQUIRED_CLAIM',
          claim: 'tenant_id',
        }),
      ])
    );
  });

  it('should fail when requireExpiration is true and exp is absent', () => {
    const token = createTestToken(undefined, { sub: 'usr_123' });
    const result = validateJwt(token, {
      requireExpiration: true,
      now: referenceTime,
    });

    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'MISSING_REQUIRED_CLAIM',
          claim: 'exp',
        }),
      ])
    );
  });

  it('should detect an expired token when current time > exp', () => {
    const token = createTestToken(undefined, {
      sub: 'usr_123',
      exp: referenceTime - 60, // Expired 60s ago
    });

    const result = validateJwt(token, { now: referenceTime });

    expect(result.valid).toBe(false);
    expect(result.expired).toBe(true);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'TOKEN_EXPIRED',
          claim: 'exp',
        }),
      ])
    );
  });

  it('should treat exact expiration instant (currentTime === exp) as expired per RFC 7519', () => {
    // RFC 7519 § 4.1.4: "The current date/time MUST be before the expiration date/time."
    // If currentTime === exp, current time is NOT before expiration date/time -> expired!
    const token = createTestToken(undefined, {
      exp: referenceTime,
    });

    const result = validateJwt(token, { now: referenceTime });

    expect(result.valid).toBe(false);
    expect(result.expired).toBe(true);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'TOKEN_EXPIRED',
        }),
      ])
    );
  });

  it('should validate future expiration as not expired', () => {
    const token = createTestToken(undefined, {
      exp: referenceTime + 60,
    });

    const result = validateJwt(token, { now: referenceTime });

    expect(result.valid).toBe(true);
    expect(result.expired).toBe(false);
  });

  it('should reject invalid NumericDate types for exp, nbf, and iat without coercing', () => {
    // String number "1700000000"
    const stringExpToken = createTestToken(undefined, { exp: '1700000000' });
    const res1 = validateJwt(stringExpToken, { now: referenceTime });
    expect(res1.valid).toBe(false);
    expect(res1.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'INVALID_CLAIM_TYPE',
          claim: 'exp',
        }),
      ])
    );

    // Object for nbf
    const objNbfToken = createTestToken(undefined, { nbf: { date: referenceTime } });
    const res2 = validateJwt(objNbfToken, { now: referenceTime });
    expect(res2.valid).toBe(false);
    expect(res2.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'INVALID_CLAIM_TYPE',
          claim: 'nbf',
        }),
      ])
    );

    // Array for iat
    const arrIatToken = createTestToken(undefined, { iat: [referenceTime] });
    const res3 = validateJwt(arrIatToken, { now: referenceTime });
    expect(res3.valid).toBe(false);
    expect(res3.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'INVALID_CLAIM_TYPE',
          claim: 'iat',
        }),
      ])
    );
  });

  it('should detect not yet valid tokens when current time < nbf', () => {
    const token = createTestToken(undefined, {
      sub: 'usr_123',
      nbf: referenceTime + 120, // 2 minutes in the future
    });

    const result = validateJwt(token, { now: referenceTime });

    expect(result.valid).toBe(false);
    expect(result.notYetValid).toBe(true);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'TOKEN_NOT_YET_VALID',
          claim: 'nbf',
        }),
      ])
    );
  });

  it('should warn when iat is in the future', () => {
    const token = createTestToken(undefined, {
      iat: referenceTime + 300,
    });

    const result = validateJwt(token, { now: referenceTime });
    expect(result.warnings).toContain('Token "iat" (issued-at) timestamp is in the future');
  });

  it('should validate issuer (iss) correctly against string or string array', () => {
    const token = createTestToken(undefined, { iss: 'https://auth.example.com' });

    // Matching single string
    const resMatch = validateJwt(token, {
      issuer: 'https://auth.example.com',
      now: referenceTime,
    });
    expect(resMatch.valid).toBe(true);

    // Matching in array
    const resArrayMatch = validateJwt(token, {
      issuer: ['https://other.com', 'https://auth.example.com'],
      now: referenceTime,
    });
    expect(resArrayMatch.valid).toBe(true);

    // Mismatched
    const resMismatch = validateJwt(token, {
      issuer: 'https://wrong.example.com',
      now: referenceTime,
    });
    expect(resMismatch.valid).toBe(false);
    expect(resMismatch.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'ISSUER_MISMATCH',
          claim: 'iss',
        }),
      ])
    );
  });

  it('should validate audience (aud) when token aud is string or string array', () => {
    // Single string aud matching
    const singleAudToken = createTestToken(undefined, { aud: 'api://my-service' });
    expect(
      validateJwt(singleAudToken, { audience: 'api://my-service', now: referenceTime }).valid
    ).toBe(true);

    // Array aud matching
    const arrayAudToken = createTestToken(undefined, {
      aud: ['api://billing', 'api://my-service'],
    });
    expect(
      validateJwt(arrayAudToken, { audience: 'api://my-service', now: referenceTime }).valid
    ).toBe(true);

    // Mismatch
    expect(
      validateJwt(arrayAudToken, { audience: 'api://admin', now: referenceTime }).valid
    ).toBe(false);
  });

  it('should honor clock tolerance seconds for expired and notYetValid boundaries', () => {
    // Token expired 10 seconds ago
    const expiredToken = createTestToken(undefined, {
      exp: referenceTime - 10,
    });

    // Without tolerance: fails
    expect(validateJwt(expiredToken, { now: referenceTime }).valid).toBe(false);

    // With 15s tolerance: passes!
    expect(
      validateJwt(expiredToken, {
        now: referenceTime,
        clockToleranceSeconds: 15,
      }).valid
    ).toBe(true);

    // Token valid in 10 seconds (nbf)
    const futureNbfToken = createTestToken(undefined, {
      nbf: referenceTime + 10,
    });

    // Without tolerance: fails
    expect(validateJwt(futureNbfToken, { now: referenceTime }).valid).toBe(false);

    // With 15s tolerance: passes!
    expect(
      validateJwt(futureNbfToken, {
        now: referenceTime,
        clockToleranceSeconds: 15,
      }).valid
    ).toBe(true);
  });

  it('should accept Date instance for now reference time', () => {
    const token = createTestToken(undefined, {
      exp: 1700000000,
    });

    const dateBefore = new Date('2023-11-14T20:00:00.000Z'); // timestamp < 1700000000
    expect(validateJwt(token, { now: dateBefore }).valid).toBe(true);

    const dateAfter = new Date('2023-11-15T00:00:00.000Z'); // timestamp > 1700000000
    expect(validateJwt(token, { now: dateAfter }).valid).toBe(false);
  });

  it('should collect multiple simultaneous errors without aborting at the first failure', () => {
    const token = createTestToken(undefined, {
      exp: referenceTime - 100, // Expired
      iss: 'wrong-issuer',      // Issuer mismatch
      // missing 'role'
    });

    const result = validateJwt(token, {
      now: referenceTime,
      issuer: 'expected-issuer',
      requiredClaims: ['role'],
    });

    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
    const codes = result.errors.map((e) => e.code);
    expect(codes).toContain('TOKEN_EXPIRED');
    expect(codes).toContain('ISSUER_MISMATCH');
    expect(codes).toContain('MISSING_REQUIRED_CLAIM');
  });

  it('should safely return structured error when token is malformed without throwing', () => {
    const malformedToken = 'not.a-valid-jwt.token!';
    const result = validateJwt(malformedToken);

    expect(result.valid).toBe(false);
    expect(result.structureValid).toBe(false);
    expect(result.claimsValid).toBe(false);
    expect(result.signatureVerified).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});
