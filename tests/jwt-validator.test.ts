import { describe, it, expect } from 'vitest';
import { validateJwt, ErrorCodes } from '../src/index.js';
import {
  createTestToken,
  createUnsecuredToken,
  encodeBase64UrlUnpadded,
  TEST_EPOCH,
} from './helpers/test-tokens.js';

describe('jwt-validator: validateJwt comprehensive test matrix', () => {
  const referenceTime = TEST_EPOCH; // 1700000000

  describe('A. Structural validation without throwing', () => {
    it('returns valid: true and structureValid: true for well-formed tokens meeting default rules', () => {
      const token = createTestToken(
        { alg: 'HS256', typ: 'JWT' },
        { sub: 'usr_1', exp: referenceTime + 3600 }
      );
      const result = validateJwt(token, { now: referenceTime });

      expect(result.valid).toBe(true);
      expect(result.structureValid).toBe(true);
      expect(result.claimsValid).toBe(true);
      expect(result.signatureVerified).toBe(false);
      expect(result.errors).toHaveLength(0);
    });

    it('returns structured failure for non-string input without throwing', () => {
      // @ts-expect-error testing invalid runtime types
      const resNull = validateJwt(null);
      expect(resNull.valid).toBe(false);
      expect(resNull.structureValid).toBe(false);
      expect(resNull.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_TOKEN_TYPE);

      // @ts-expect-error testing invalid runtime types
      const resNum = validateJwt(12345);
      expect(resNum.valid).toBe(false);
      expect(resNum.structureValid).toBe(false);
      expect(resNum.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_TOKEN_TYPE);
    });

    it('returns structured failure for invalid segment counts without throwing', () => {
      const res1 = validateJwt('only-one-segment');
      expect(res1.valid).toBe(false);
      expect(res1.structureValid).toBe(false);
      expect(res1.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_SEGMENT_COUNT);

      const res4 = validateJwt('a.b.c.d');
      expect(res4.valid).toBe(false);
      expect(res4.structureValid).toBe(false);
      expect(res4.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_SEGMENT_COUNT);
    });

    it('returns structured failure for empty header or empty payload', () => {
      const resEmptyHeader = validateJwt('.eyJzdWIiOiIxMjMifQ.sig');
      expect(resEmptyHeader.valid).toBe(false);
      expect(resEmptyHeader.structureValid).toBe(false);
      expect(resEmptyHeader.errors[0]?.code).toBe(ErrorCodes.ERR_EMPTY_SEGMENT);

      const resEmptyPayload = validateJwt('eyJhbGciOiJIUzI1NiJ9..sig');
      expect(resEmptyPayload.valid).toBe(false);
      expect(resEmptyPayload.structureValid).toBe(false);
      expect(resEmptyPayload.errors[0]?.code).toBe(ErrorCodes.ERR_EMPTY_SEGMENT);
    });

    it('returns structured failure for invalid Base64URL characters in segments', () => {
      const badToken = 'eyJhbGciOiJIUzI1NiJ9!.eyJzdWIiOiIxMjMifQ.sig';
      const result = validateJwt(badToken);

      expect(result.valid).toBe(false);
      expect(result.structureValid).toBe(false);
      expect(result.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_BASE64URL);
    });

    it('returns structured failure for invalid JSON in header or payload', () => {
      const notJson = encodeBase64UrlUnpadded('not json');
      const validPart = encodeBase64UrlUnpadded('{"sub":"123"}');

      const resHeader = validateJwt(`${notJson}.${validPart}.sig`);
      expect(resHeader.valid).toBe(false);
      expect(resHeader.structureValid).toBe(false);
      expect(resHeader.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_JSON);

      const resPayload = validateJwt(`${validPart}.${notJson}.sig`);
      expect(resPayload.valid).toBe(false);
      expect(resPayload.structureValid).toBe(false);
      expect(resPayload.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_JSON);
    });

    it('returns structured failure for non-object JSON values (arrays, primitives)', () => {
      const arrayPart = encodeBase64UrlUnpadded('[1, 2, 3]');
      const validPart = encodeBase64UrlUnpadded('{"sub":"123"}');

      const resArray = validateJwt(`${validPart}.${arrayPart}.sig`);
      expect(resArray.valid).toBe(false);
      expect(resArray.structureValid).toBe(false);
      expect(resArray.errors[0]?.code).toBe(ErrorCodes.ERR_INVALID_JSON_OBJECT);
    });

    it('never reports signatureVerified as true under any circumstances', () => {
      const validToken = createTestToken();
      const result = validateJwt(validToken);
      expect(result.signatureVerified).toBe(false);
    });
  });

  describe('B. Required claims policy and presence semantics', () => {
    it('passes when no required claims are specified', () => {
      const token = createTestToken(undefined, { foo: 'bar' });
      expect(validateJwt(token).valid).toBe(true);
    });

    it('passes when empty requiredClaims array is provided', () => {
      const token = createTestToken(undefined, { foo: 'bar' });
      expect(validateJwt(token, { requiredClaims: [] }).valid).toBe(true);
    });

    it('validates single and multiple required claims all present', () => {
      const token = createTestToken(undefined, {
        sub: 'usr_1',
        org_id: 'org_99',
        tier: 'gold',
      });

      const res1 = validateJwt(token, { requiredClaims: ['sub'] });
      expect(res1.valid).toBe(true);

      const res3 = validateJwt(token, { requiredClaims: ['sub', 'org_id', 'tier'] });
      expect(res3.valid).toBe(true);
    });

    it('fails when one required claim is missing', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      const res = validateJwt(token, { requiredClaims: ['sub', 'org_id'] });

      expect(res.valid).toBe(false);
      expect(res.claimsValid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({
          code: 'MISSING_REQUIRED_CLAIM',
          claim: 'org_id',
        }),
      ]);
    });

    it('reports all missing required claims when multiple are missing', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      const res = validateJwt(token, { requiredClaims: ['sub', 'claim_a', 'claim_b', 'claim_c'] });

      expect(res.valid).toBe(false);
      expect(res.errors).toHaveLength(3);
      expect(res.errors.map((e) => e.claim)).toEqual(['claim_a', 'claim_b', 'claim_c']);
    });

    it('treats present claims with valid false, numeric 0, empty string, and null as PRESENT', () => {
      const token = createTestToken(undefined, {
        boolClaim: false,
        zeroClaim: 0,
        emptyClaim: '',
        nullClaim: null,
      });

      const res = validateJwt(token, {
        requiredClaims: ['boolClaim', 'zeroClaim', 'emptyClaim', 'nullClaim'],
      });

      expect(res.valid).toBe(true);
      expect(res.errors).toHaveLength(0);
    });

    it('returns ERR_INVALID_OPTIONS when requiredClaims is not an array of strings', () => {
      const token = createTestToken();
      // @ts-expect-error testing invalid runtime options
      const resNonArray = validateJwt(token, { requiredClaims: 'sub' });
      expect(resNonArray.valid).toBe(false);
      expect(resNonArray.errors[0]?.code).toBe('ERR_INVALID_OPTIONS');

      // @ts-expect-error testing invalid array items
      const resBadItems = validateJwt(token, { requiredClaims: [123] });
      expect(resBadItems.valid).toBe(false);
      expect(resBadItems.errors[0]?.code).toBe('ERR_INVALID_OPTIONS');
    });
  });

  describe('C. Expiration claim (exp) semantics and boundaries', () => {
    it('passes for valid future expiration', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 3600 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(true);
      expect(res.expired).toBe(false);
    });

    it('fails when token has expired in the past', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 1 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(false);
      expect(res.expired).toBe(true);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'TOKEN_EXPIRED', claim: 'exp' }),
      ]);
    });

    it('treats exact expiration instant (now === exp) as EXPIRED per RFC 7519 § 4.1.4', () => {
      const token = createTestToken(undefined, { exp: referenceTime });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(false);
      expect(res.expired).toBe(true);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'TOKEN_EXPIRED', claim: 'exp' }),
      ]);
    });

    it('passes 1 second before expiration boundary (now === exp - 1)', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 1 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(true);
      expect(res.expired).toBe(false);
    });

    it('treats missing exp with requireExpiration: false as valid with warning', () => {
      const token = createTestToken(undefined, { sub: 'usr_no_exp' });
      const res = validateJwt(token, { requireExpiration: false });

      expect(res.valid).toBe(true);
      expect(res.expired).toBe(false);
      expect(res.warnings).toContain('Token does not contain an "exp" (expiration) claim');
    });

    it('fails when requireExpiration: true and exp is absent', () => {
      const token = createTestToken(undefined, { sub: 'usr_no_exp' });
      const res = validateJwt(token, { requireExpiration: true });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'MISSING_REQUIRED_CLAIM', claim: 'exp' }),
      ]);
    });

    it('handles exp equal to zero as expired relative to modern times', () => {
      const token = createTestToken(undefined, { exp: 0 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(false);
      expect(res.expired).toBe(true);
    });

    it('handles negative exp as expired', () => {
      const token = createTestToken(undefined, { exp: -1000 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(false);
      expect(res.expired).toBe(true);
    });

    it('supports fractional NumericDate values for exp', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 0.5 });
      // At referenceTime (now < exp): valid
      expect(validateJwt(token, { now: referenceTime }).valid).toBe(true);
      // At referenceTime + 1 (now > exp): expired
      expect(validateJwt(token, { now: referenceTime + 1 }).valid).toBe(false);
    });

    it('supports very large NumericDate values without overflow', () => {
      const farFuture = 253402300799; // Year 9999
      const token = createTestToken(undefined, { exp: farFuture });
      expect(validateJwt(token, { now: referenceTime }).valid).toBe(true);
    });

    it('rejects invalid claim types for exp (string, boolean, null, object, array, NaN, Infinity)', () => {
      const invalidValues = [
        '1700000000',
        true,
        false,
        null,
        {},
        [1700000000],
        Number.NaN,
        Infinity,
        -Infinity,
      ];

      for (const val of invalidValues) {
        const token = createTestToken(undefined, { exp: val });
        const res = validateJwt(token, { now: referenceTime });

        expect(res.valid).toBe(false);
        expect(res.errors).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ code: 'INVALID_CLAIM_TYPE', claim: 'exp' }),
          ])
        );
      }
    });
  });

  describe('D. Not-before claim (nbf) semantics', () => {
    it('passes when nbf is in the past', () => {
      const token = createTestToken(undefined, { nbf: referenceTime - 100 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(true);
      expect(res.notYetValid).toBe(false);
    });

    it('passes when now is exactly equal to nbf per RFC 7519 § 4.1.5', () => {
      // Current date/time MUST be after or equal to not-before date/time
      const token = createTestToken(undefined, { nbf: referenceTime });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(true);
      expect(res.notYetValid).toBe(false);
    });

    it('fails when nbf is in the future', () => {
      const token = createTestToken(undefined, { nbf: referenceTime + 1 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(false);
      expect(res.notYetValid).toBe(true);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'TOKEN_NOT_YET_VALID', claim: 'nbf' }),
      ]);
    });

    it('rejects invalid claim types for nbf', () => {
      const invalidValues = ['1700000000', true, null, {}, [], Number.NaN];
      for (const val of invalidValues) {
        const token = createTestToken(undefined, { nbf: val });
        const res = validateJwt(token, { now: referenceTime });

        expect(res.valid).toBe(false);
        expect(res.errors).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ code: 'INVALID_CLAIM_TYPE', claim: 'nbf' }),
          ])
        );
      }
    });
  });

  describe('E. Issued-at claim (iat) validation', () => {
    it('passes when numeric iat is present in the past', () => {
      const token = createTestToken(undefined, { iat: referenceTime - 60 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(true);
      expect(res.warnings).not.toContain('Token "iat" (issued-at) timestamp is in the future');
    });

    it('emits warning when iat is in the future but does not fail by default', () => {
      const token = createTestToken(undefined, { iat: referenceTime + 300 });
      const res = validateJwt(token, { now: referenceTime });

      expect(res.valid).toBe(true);
      expect(res.warnings).toContain('Token "iat" (issued-at) timestamp is in the future');
    });

    it('rejects invalid claim types for iat', () => {
      const invalidValues = ['1700000000', false, null, {}, []];
      for (const val of invalidValues) {
        const token = createTestToken(undefined, { iat: val });
        const res = validateJwt(token, { now: referenceTime });

        expect(res.valid).toBe(false);
        expect(res.errors).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ code: 'INVALID_CLAIM_TYPE', claim: 'iat' }),
          ])
        );
      }
    });
  });

  describe('F. Issuer (iss) validation', () => {
    it('validates exact string issuer match', () => {
      const token = createTestToken(undefined, { iss: 'https://auth.company.com' });
      expect(
        validateJwt(token, { issuer: 'https://auth.company.com' }).valid
      ).toBe(true);
    });

    it('validates issuer against array of allowed issuers', () => {
      const token = createTestToken(undefined, { iss: 'https://auth-eu.company.com' });
      expect(
        validateJwt(token, {
          issuer: ['https://auth-us.company.com', 'https://auth-eu.company.com'],
        }).valid
      ).toBe(true);
    });

    it('fails when issuer mismatches', () => {
      const token = createTestToken(undefined, { iss: 'https://auth-wrong.company.com' });
      const res = validateJwt(token, { issuer: 'https://auth-expected.company.com' });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'ISSUER_MISMATCH', claim: 'iss' }),
      ]);
    });

    it('fails when issuer claim is missing and issuer validation is configured', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      const res = validateJwt(token, { issuer: 'https://auth.company.com' });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'MISSING_REQUIRED_CLAIM', claim: 'iss' }),
      ]);
    });

    it('enforces strict case sensitivity for issuer', () => {
      const token = createTestToken(undefined, { iss: 'https://AUTH.company.com' });
      expect(
        validateJwt(token, { issuer: 'https://auth.company.com' }).valid
      ).toBe(false);
    });

    it('does not silently trim spaces in issuer', () => {
      const token = createTestToken(undefined, { iss: ' https://auth.company.com ' });
      expect(
        validateJwt(token, { issuer: 'https://auth.company.com' }).valid
      ).toBe(false);
    });

    it('rejects non-string issuer claim in payload with INVALID_CLAIM_TYPE', () => {
      const token = createTestToken(undefined, { iss: 12345 });
      const res = validateJwt(token, { issuer: '12345' });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'INVALID_CLAIM_TYPE', claim: 'iss' }),
      ]);
    });

    it('returns ERR_INVALID_OPTIONS when options.issuer is invalid type', () => {
      const token = createTestToken();
      // @ts-expect-error testing invalid option type
      const res = validateJwt(token, { issuer: 12345 });

      expect(res.valid).toBe(false);
      expect(res.errors[0]?.code).toBe('ERR_INVALID_OPTIONS');
    });
  });

  describe('G. Audience (aud) validation', () => {
    it('validates single string audience match', () => {
      const token = createTestToken(undefined, { aud: 'api://backend' });
      expect(validateJwt(token, { audience: 'api://backend' }).valid).toBe(true);
    });

    it('validates token audience array containing expected audience', () => {
      const token = createTestToken(undefined, { aud: ['api://backend', 'api://mobile'] });
      expect(validateJwt(token, { audience: 'api://mobile' }).valid).toBe(true);
    });

    it('validates array of allowed audiences matching token audience', () => {
      const token = createTestToken(undefined, { aud: 'api://service-b' });
      expect(
        validateJwt(token, { audience: ['api://service-a', 'api://service-b'] }).valid
      ).toBe(true);
    });

    it('fails when token audience mismatches', () => {
      const token = createTestToken(undefined, { aud: 'api://backend' });
      const res = validateJwt(token, { audience: 'api://frontend' });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'AUDIENCE_MISMATCH', claim: 'aud' }),
      ]);
    });

    it('fails when token audience is missing and audience validation is configured', () => {
      const token = createTestToken(undefined, { sub: 'usr_1' });
      const res = validateJwt(token, { audience: 'api://backend' });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'MISSING_REQUIRED_CLAIM', claim: 'aud' }),
      ]);
    });

    it('fails when token audience is an empty array', () => {
      const token = createTestToken(undefined, { aud: [] });
      const res = validateJwt(token, { audience: 'api://backend' });

      expect(res.valid).toBe(false);
      expect(res.errors).toEqual([
        expect.objectContaining({ code: 'AUDIENCE_MISMATCH', claim: 'aud' }),
      ]);
    });

    it('rejects invalid audience types in token payload (number, object, non-string array)', () => {
      const badTokens = [
        createTestToken(undefined, { aud: 123 }),
        createTestToken(undefined, { aud: { client: 'abc' } }),
        createTestToken(undefined, { aud: ['valid-str', 123] }),
      ];

      for (const t of badTokens) {
        const res = validateJwt(t, { audience: 'valid-str' });
        expect(res.valid).toBe(false);
        expect(res.errors).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ code: 'INVALID_CLAIM_TYPE', claim: 'aud' }),
          ])
        );
      }
    });

    it('enforces case sensitivity on audience', () => {
      const token = createTestToken(undefined, { aud: 'API://BACKEND' });
      expect(validateJwt(token, { audience: 'api://backend' }).valid).toBe(false);
    });

    it('returns ERR_INVALID_OPTIONS when options.audience is invalid type', () => {
      const token = createTestToken();
      // @ts-expect-error testing invalid option type
      const res = validateJwt(token, { audience: 12345 });

      expect(res.valid).toBe(false);
      expect(res.errors[0]?.code).toBe('ERR_INVALID_OPTIONS');
    });
  });

  describe('H. Clock tolerance and injectable reference time', () => {
    it('supports 0 clock tolerance as default', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 1 });
      expect(validateJwt(token, { now: referenceTime, clockToleranceSeconds: 0 }).valid).toBe(false);
    });

    it('tolerates expired token when expiration falls within clock tolerance', () => {
      // Expired 15s ago
      const token = createTestToken(undefined, { exp: referenceTime - 15 });

      // Tolerance of 10s: still expired
      expect(
        validateJwt(token, { now: referenceTime, clockToleranceSeconds: 10 }).valid
      ).toBe(false);

      // Tolerance of 20s: tolerated!
      expect(
        validateJwt(token, { now: referenceTime, clockToleranceSeconds: 20 }).valid
      ).toBe(true);
    });

    it('tolerates future nbf token when within clock tolerance', () => {
      // Valid in 15 seconds
      const token = createTestToken(undefined, { nbf: referenceTime + 15 });

      // Tolerance 10s: not yet valid
      expect(
        validateJwt(token, { now: referenceTime, clockToleranceSeconds: 10 }).valid
      ).toBe(false);

      // Tolerance 20s: tolerated!
      expect(
        validateJwt(token, { now: referenceTime, clockToleranceSeconds: 20 }).valid
      ).toBe(true);
    });

    it('returns ERR_INVALID_CLOCK_TOLERANCE for negative or invalid tolerance values', () => {
      const token = createTestToken();
      const resNeg = validateJwt(token, { clockToleranceSeconds: -5 });
      expect(resNeg.valid).toBe(false);
      expect(resNeg.errors[0]?.code).toBe('ERR_INVALID_CLOCK_TOLERANCE');

      // @ts-expect-error testing invalid tolerance type
      const resStr = validateJwt(token, { clockToleranceSeconds: '10' });
      expect(resStr.valid).toBe(false);
      expect(resStr.errors[0]?.code).toBe('ERR_INVALID_CLOCK_TOLERANCE');

      const resNaN = validateJwt(token, { clockToleranceSeconds: Number.NaN });
      expect(resNaN.valid).toBe(false);
      expect(resNaN.errors[0]?.code).toBe('ERR_INVALID_CLOCK_TOLERANCE');
    });

    it('returns ERR_INVALID_REFERENCE_TIME for invalid Date reference times', () => {
      const token = createTestToken();
      const resInvalidDate = validateJwt(token, { now: new Date('invalid-date') });

      expect(resInvalidDate.valid).toBe(false);
      expect(resInvalidDate.errors[0]?.code).toBe('ERR_INVALID_REFERENCE_TIME');
    });

    it('returns ERR_INVALID_REFERENCE_TIME for invalid numeric reference times (NaN, non-finite)', () => {
      const token = createTestToken();
      const resNaN = validateJwt(token, { now: Number.NaN });
      expect(resNaN.valid).toBe(false);
      expect(resNaN.errors[0]?.code).toBe('ERR_INVALID_REFERENCE_TIME');

      const resInf = validateJwt(token, { now: Infinity });
      expect(resInf.valid).toBe(false);
      expect(resInf.errors[0]?.code).toBe('ERR_INVALID_REFERENCE_TIME');
    });

    it('accepts milliseconds timestamp for now (> 1e11) and converts correctly', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 100 });
      // referenceTime * 1000 in ms
      const resMs = validateJwt(token, { now: referenceTime * 1000 });
      expect(resMs.valid).toBe(true);
    });
  });

  describe('I. Multiple simultaneous failures', () => {
    it('discovers all failures simultaneously without early termination', () => {
      const token = createTestToken(undefined, {
        exp: referenceTime - 100, // Expired
        nbf: referenceTime + 100, // Not yet valid
        iss: 'wrong-iss',         // Issuer mismatch
        aud: 'wrong-aud',         // Audience mismatch
        // missing 'tenant_id'
      });

      const res = validateJwt(token, {
        now: referenceTime,
        issuer: 'expected-iss',
        audience: 'expected-aud',
        requiredClaims: ['tenant_id'],
      });

      expect(res.valid).toBe(false);
      expect(res.expired).toBe(true);
      expect(res.notYetValid).toBe(true);
      expect(res.errors.length).toBeGreaterThanOrEqual(4);

      const codes = res.errors.map((e) => e.code);
      expect(codes).toContain('TOKEN_EXPIRED');
      expect(codes).toContain('TOKEN_NOT_YET_VALID');
      expect(codes).toContain('ISSUER_MISMATCH');
      expect(codes).toContain('AUDIENCE_MISMATCH');
      expect(codes).toContain('MISSING_REQUIRED_CLAIM');
    });
  });

  describe('J. Immutability and result integrity', () => {
    it('does not mutate input token or parsed payload object', () => {
      const originalPayload = { sub: 'usr_123', custom: 'value' };
      const token = createTestToken(undefined, originalPayload);

      validateJwt(token, {
        issuer: 'iss',
        requiredClaims: ['custom'],
        now: referenceTime,
      });

      // Original payload unmodified
      expect(originalPayload).toEqual({ sub: 'usr_123', custom: 'value' });
    });

    it('warns for unsecured tokens with alg: "none"', () => {
      const token = createUnsecuredToken({ sub: 'usr_1' });
      const res = validateJwt(token);

      expect(res.warnings).toContain('Token specifies algorithm "none" (unsecured token)');
    });
  });
});
