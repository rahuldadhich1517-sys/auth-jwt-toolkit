import { describe, it, expect } from 'vitest';
import {
  decodeJwt,
  validateJwt,
  inspectJwt,
  getJwtExpiry,
  isJwtExpired,
  getJwtRemainingValidity,
  JwtParseError,
  JwtExpiryError,
} from '../src/index.js';
import {
  createTestToken,
  TEST_EPOCH,
} from './helpers/test-tokens.js';

describe('cross-utility integration: 9 comprehensive real-world scenarios', () => {
  const referenceTime = TEST_EPOCH; // 1700000000 (2023-11-14T22:13:20.000Z)

  it('Scenario 1: Normal unexpired token end-to-end lifecycle', () => {
    const token = createTestToken(
      { alg: 'RS256', typ: 'JWT', kid: 'rsa-prod-1' },
      {
        iss: 'https://auth.enterprise.io',
        sub: 'user_998877',
        aud: ['https://api.enterprise.io', 'https://billing.enterprise.io'],
        iat: referenceTime - 300,
        nbf: referenceTime - 60,
        exp: referenceTime + 3600,
        email: 'alex@enterprise.io',
        tenantId: 'tenant_abc',
      },
      'c2lnbmF0dXJlX2FseF9wcm9kXzAwMQ'
    );

    // 1. Decode
    const decoded = decodeJwt(token);
    expect(decoded.header['alg']).toBe('RS256');
    expect(decoded.payload['sub']).toBe('user_998877');
    expect(decoded.payload['email']).toBe('alex@enterprise.io');
    expect(decoded.signature).toBe('c2lnbmF0dXJlX2FseF9wcm9kXzAwMQ');

    // 2. Validate
    const validation = validateJwt(token, {
      issuer: 'https://auth.enterprise.io',
      audience: 'https://api.enterprise.io',
      requiredClaims: ['sub', 'tenantId', 'email'],
      requireExpiration: true,
      now: referenceTime,
    });
    expect(validation.valid).toBe(true);
    expect(validation.structureValid).toBe(true);
    expect(validation.claimsValid).toBe(true);
    expect(validation.expired).toBe(false);
    expect(validation.notYetValid).toBe(false);
    expect(validation.signatureVerified).toBe(false);

    // 3. Inspect
    const inspection = inspectJwt(token, { now: referenceTime });
    expect(inspection.claims.iss).toBe('https://auth.enterprise.io');
    expect(inspection.claims.sub).toBe('user_998877');
    expect(inspection.claims.exp?.iso).toBe('2023-11-14T23:13:20.000Z');
    expect(inspection.validity.isExpired).toBe(false);
    expect(inspection.validity.remainingValiditySeconds).toBe(3600);
    expect(inspection.signatureVerified).toBe(false);
    expect(inspection.signature.verified).toBe(false);

    // 4. Expiry utilities
    const expiry = getJwtExpiry(token, { now: referenceTime });
    expect(expiry.hasExpiration).toBe(true);
    expect(expiry.isExpired).toBe(false);
    expect(expiry.remainingValiditySeconds).toBe(3600);

    expect(isJwtExpired(token, { now: referenceTime })).toBe(false);
    expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(3600);
  });

  it('Scenario 2: Expired token cross-utility handling', () => {
    const expiredToken = createTestToken(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'usr_expired', exp: referenceTime - 120 }
    );

    // Decoder still reads the structurally valid token
    const decoded = decodeJwt(expiredToken);
    expect(decoded.payload['sub']).toBe('usr_expired');

    // Validator detects expiration
    const validation = validateJwt(expiredToken, { now: referenceTime });
    expect(validation.valid).toBe(false);
    expect(validation.structureValid).toBe(true);
    expect(validation.claimsValid).toBe(false);
    expect(validation.expired).toBe(true);
    expect(validation.errors).toEqual([
      expect.objectContaining({ code: 'TOKEN_EXPIRED', claim: 'exp' }),
    ]);

    // Inspector reports expired state
    const inspection = inspectJwt(expiredToken, { now: referenceTime });
    expect(inspection.validity.isExpired).toBe(true);
    expect(inspection.validity.remainingValiditySeconds).toBe(-120);
    expect(inspection.warnings).toContain('Token is expired');

    // Expiry utilities return documented expired results
    const expiry = getJwtExpiry(expiredToken, { now: referenceTime });
    expect(expiry.isExpired).toBe(true);
    expect(expiry.remainingValiditySeconds).toBe(-120);

    expect(isJwtExpired(expiredToken, { now: referenceTime })).toBe(true);
    expect(getJwtRemainingValidity(expiredToken, { now: referenceTime })).toBe(-120);
  });

  it('Scenario 3: Token with no expiration claim (exp absent)', () => {
    const noExpToken = createTestToken(undefined, { sub: 'usr_immortal', role: 'service' });

    // Decoder succeeds
    const decoded = decodeJwt(noExpToken);
    expect(decoded.payload['sub']).toBe('usr_immortal');

    // Validator allows missing exp if requireExpiration is false (default), but warns
    const defaultVal = validateJwt(noExpToken);
    expect(defaultVal.valid).toBe(true);
    expect(defaultVal.expired).toBe(false);
    expect(defaultVal.warnings).toContain('Token does not contain an "exp" (expiration) claim');

    // Validator rejects if requireExpiration is true
    const strictVal = validateJwt(noExpToken, { requireExpiration: true });
    expect(strictVal.valid).toBe(false);
    expect(strictVal.errors).toEqual([
      expect.objectContaining({ code: 'MISSING_REQUIRED_CLAIM', claim: 'exp' }),
    ]);

    // Inspector reports missing exp
    const inspection = inspectJwt(noExpToken);
    expect(inspection.validity.hasExpiration).toBe(false);
    expect(inspection.validity.isExpired).toBeNull();
    expect(inspection.validity.remainingValiditySeconds).toBeNull();
    expect(inspection.warnings).toContain('Token does not specify an expiration (exp) claim');

    // Expiry helpers distinguish missing exp from active/expired
    const expiry = getJwtExpiry(noExpToken);
    expect(expiry.hasExpiration).toBe(false);
    expect(expiry.exp).toBeNull();
    expect(expiry.remainingValiditySeconds).toBeNull();

    // isJwtExpired throws by default to prevent assuming infinite validity
    expect(() => isJwtExpired(noExpToken)).toThrowError(JwtExpiryError);
    // or returns configured fallback
    expect(isJwtExpired(noExpToken, { treatMissingExpAs: 'expired' })).toBe(true);
    expect(isJwtExpired(noExpToken, { treatMissingExpAs: 'not-expired' })).toBe(false);

    // getJwtRemainingValidity returns null
    expect(getJwtRemainingValidity(noExpToken)).toBeNull();
  });

  it('Scenario 4: Token not yet valid (future nbf claim)', () => {
    const futureNbfToken = createTestToken(undefined, {
      sub: 'usr_scheduled',
      nbf: referenceTime + 600, // Valid in 10 minutes
      exp: referenceTime + 3600,
    });

    // Decoder decodes correctly
    expect(decodeJwt(futureNbfToken).payload['sub']).toBe('usr_scheduled');

    // Validator flags notYetValid: true, expired: false
    const validation = validateJwt(futureNbfToken, { now: referenceTime });
    expect(validation.valid).toBe(false);
    expect(validation.notYetValid).toBe(true);
    expect(validation.expired).toBe(false); // MUST NOT be classified as expired!
    expect(validation.errors).toEqual([
      expect.objectContaining({ code: 'TOKEN_NOT_YET_VALID', claim: 'nbf' }),
    ]);

    // Inspector flags isNotYetValid: true, isExpired: false
    const inspection = inspectJwt(futureNbfToken, { now: referenceTime });
    expect(inspection.validity.isNotYetValid).toBe(true);
    expect(inspection.validity.isExpired).toBe(false);
    expect(inspection.warnings).toContain('Token is not yet valid (nbf is in the future)');

    // Expiry says not expired
    expect(isJwtExpired(futureNbfToken, { now: referenceTime })).toBe(false);
  });

  it('Scenario 5: Issuer and audience mismatch verification', () => {
    const mismatchToken = createTestToken(undefined, {
      iss: 'https://identity.actual.com',
      aud: 'https://service-a.com',
    });

    // Decoder still reads token correctly
    const decoded = decodeJwt(mismatchToken);
    expect(decoded.payload['iss']).toBe('https://identity.actual.com');
    expect(decoded.payload['aud']).toBe('https://service-a.com');

    // Validator reports both ISSUER_MISMATCH and AUDIENCE_MISMATCH
    const val = validateJwt(mismatchToken, {
      issuer: 'https://identity.expected.com',
      audience: 'https://service-b.com',
    });
    expect(val.valid).toBe(false);
    expect(val.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'ISSUER_MISMATCH', claim: 'iss' }),
        expect.objectContaining({ code: 'AUDIENCE_MISMATCH', claim: 'aud' }),
      ])
    );
  });

  it('Scenario 6: Application-specific required claims with false/0/empty presence', () => {
    const token = createTestToken(undefined, {
      sub: 'usr_1',
      isRoot: false,
      loginAttempts: 0,
      middleName: '',
      avatarUrl: null,
    });

    // Requiring present claims that have falsy values must SUCCEED
    const valPresent = validateJwt(token, {
      requiredClaims: ['isRoot', 'loginAttempts', 'middleName', 'avatarUrl'],
    });
    expect(valPresent.valid).toBe(true);

    // Requiring absent claim must FAIL
    const valMissing = validateJwt(token, {
      requiredClaims: ['isRoot', 'phoneNumber'],
    });
    expect(valMissing.valid).toBe(false);
    expect(valMissing.errors).toEqual([
      expect.objectContaining({ code: 'MISSING_REQUIRED_CLAIM', claim: 'phoneNumber' }),
    ]);
  });

  it('Scenario 7: Malformed input contract across all public utilities', () => {
    const malformedTokens = [
      'not-a-jwt',
      'header.only',
      '.emptyheader.sig',
      'header..emptypayload',
      'bad!base64url.part.sig',
    ];

    for (const token of malformedTokens) {
      // 1. Decoder throws typed JwtParseError
      expect(() => decodeJwt(token)).toThrowError(JwtParseError);

      // 2. Inspector throws typed JwtParseError
      expect(() => inspectJwt(token)).toThrowError(JwtParseError);

      // 3. Expiry helpers throw typed JwtParseError
      expect(() => getJwtExpiry(token)).toThrowError(JwtParseError);
      expect(() => isJwtExpired(token)).toThrowError(JwtParseError);
      expect(() => getJwtRemainingValidity(token)).toThrowError(JwtParseError);

      // 4. Validator DOES NOT throw; returns structured failure!
      const val = validateJwt(token);
      expect(val.valid).toBe(false);
      expect(val.structureValid).toBe(false);
      expect(val.claimsValid).toBe(false);
      expect(val.signatureVerified).toBe(false);
      expect(val.errors.length).toBeGreaterThan(0);
    }
  });

  it('Scenario 8: Unverified signature contract across all utilities', () => {
    const arbitrarySignature = 'YXJiaXRyYXJ5X2Jhc2U2NHVybF9zaWduYXR1cmU';
    const token = createTestToken(
      { alg: 'RS256' },
      { sub: 'user_spoofed', role: 'admin', exp: referenceTime + 1000 },
      arbitrarySignature
    );

    // Decoder extracts signature as opaque data
    const decoded = decodeJwt(token);
    expect(decoded.signature).toBe(arbitrarySignature);

    // Validator valid: true MUST NOT imply signature verification
    const val = validateJwt(token, { now: referenceTime });
    expect(val.valid).toBe(true);
    expect(val.signatureVerified).toBe(false);

    // Inspector explicitly flags signature as unverified
    const inspection = inspectJwt(token, { now: referenceTime });
    expect(inspection.signatureVerified).toBe(false);
    expect(inspection.signature.verified).toBe(false);
    expect(inspection.signature.present).toBe(true);
    expect(inspection.signature.segment).toBe(arbitrarySignature);
  });

  it('Scenario 9: Deterministic outputs under identical injected reference time', () => {
    const token = createTestToken(undefined, {
      exp: referenceTime + 7200,
      nbf: referenceTime - 1800,
      iat: referenceTime - 3600,
    });

    // Run 10 consecutive iterations with fixed reference time
    for (let i = 0; i < 10; i++) {
      const val = validateJwt(token, { now: referenceTime });
      expect(val.valid).toBe(true);
      expect(val.expired).toBe(false);

      const inspection = inspectJwt(token, { now: referenceTime });
      expect(inspection.validity.remainingValiditySeconds).toBe(7200);

      const expiry = getJwtExpiry(token, { now: referenceTime });
      expect(expiry.remainingValiditySeconds).toBe(7200);

      expect(isJwtExpired(token, { now: referenceTime })).toBe(false);
      expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(7200);
    }
  });
});
