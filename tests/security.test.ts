import { describe, it, expect, vi } from 'vitest';
import {
  decodeJwt,
  validateJwt,
  inspectJwt,
  isJwtExpired,
  getJwtExpiry,
  JwtParseError,
  JwtExpiryError,
} from '../src/index.js';
import { createTestToken } from './helpers/test-tokens.js';

describe('security: boundary and safety guarantees', () => {
  it('never executes JavaScript or evaluates code in payload/header values', () => {
    // Attempted code injection in payload
    const maliciousPayload = {
      sub: 'user_123',
      code1: 'process.exit(1)',
      code2: 'function() { throw new Error("exploited"); }()',
      code3: '<script>alert("xss")</script>',
      constructor: 'polluted',
      __proto__: { polluted: true },
    };

    const token = createTestToken(undefined, maliciousPayload);

    // Decoding must safely parse as inert JSON without executing
    const decoded = decodeJwt(token);
    expect(decoded.payload['code1']).toBe('process.exit(1)');
    expect(decoded.payload['constructor']).toBe('polluted');

    // Object prototype must NOT be polluted
    const cleanObj: Record<string, unknown> = {};
    expect(cleanObj['polluted']).toBeUndefined();
  });

  it('never makes network requests during decoding, validation, or inspection', () => {
    // Spy on global fetch
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const tokenWithRemoteUrls = createTestToken(
      { alg: 'RS256', jku: 'https://evil.com/jwks.json', x5u: 'https://evil.com/cert.pem' },
      { iss: 'https://evil-issuer.com/auth', sub: 'user_123' }
    );

    decodeJwt(tokenWithRemoteUrls);
    validateJwt(tokenWithRemoteUrls);
    inspectJwt(tokenWithRemoteUrls);
    getJwtExpiry(tokenWithRemoteUrls);

    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it('always marks signatureVerified as false across all utilities and result types', () => {
    const token = createTestToken({ alg: 'RS256' }, { sub: 'admin', exp: 2000000000 });

    const validationResult = validateJwt(token, { now: 1700000000 });
    expect(validationResult.valid).toBe(true);
    expect(validationResult.signatureVerified).toBe(false);

    const inspectionResult = inspectJwt(token, { now: 1700000000 });
    expect(inspectionResult.signatureVerified).toBe(false);
    expect(inspectionResult.signature.verified).toBe(false);
  });

  it('never leaks the full token or sensitive signature in error messages', () => {
    const secretSignature = 'SUPER_SECRET_SIGNATURE_VALUE_DO_NOT_LEAK_12345';
    const badToken = `eyJhbGciOiJIUzI1NiJ9.INVALID_JSON_HERE.${secretSignature}`;

    try {
      decodeJwt(badToken);
      expect.fail('Should have thrown JwtParseError');
    } catch (err) {
      expect(err).toBeInstanceOf(JwtParseError);
      const msg = (err as Error).message;
      expect(msg).not.toContain(secretSignature);
      expect(msg).not.toContain(badToken);
    }
  });

  it('does not coerce string numbers or boolean values into NumericDates', () => {
    const referenceTime = 1700000000;
    const stringExpToken = createTestToken(undefined, {
      sub: 'usr_1',
      exp: `${referenceTime + 1000}`, // String instead of number!
    });

    // validateJwt must reject rather than coerce
    const valResult = validateJwt(stringExpToken, { now: referenceTime });
    expect(valResult.valid).toBe(false);
    expect(valResult.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'INVALID_CLAIM_TYPE',
          claim: 'exp',
        }),
      ])
    );

    // isJwtExpired must throw rather than coerce
    expect(() => isJwtExpired(stringExpToken, { now: referenceTime })).toThrowError(
      JwtExpiryError
    );

    // getJwtExpiry must throw rather than coerce
    expect(() => getJwtExpiry(stringExpToken, { now: referenceTime })).toThrowError(
      JwtExpiryError
    );
  });

  it('strictly rejects malformed Base64URL characters in all segments', () => {
    const badChars = ['@', '#', '$', '%', '^', '&', '*', '(', ')', ' ', '\n', '\t'];

    for (const char of badChars) {
      const badToken = `eyJhbGciOi${char}JIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig`;
      expect(() => decodeJwt(badToken)).toThrowError(JwtParseError);

      const val = validateJwt(badToken);
      expect(val.valid).toBe(false);
      expect(val.structureValid).toBe(false);
    }
  });

  it('does not treat alg: "none" as verified or trusted', () => {
    const unsecuredToken = createTestToken(
      { alg: 'none', typ: 'JWT' },
      { sub: 'admin', role: 'superuser', exp: 2000000000 },
      ''
    );

    const valResult = validateJwt(unsecuredToken, { now: 1700000000 });
    expect(valResult.signatureVerified).toBe(false);
    expect(valResult.warnings).toContain('Token specifies algorithm "none" (unsecured token)');

    const inspectResult = inspectJwt(unsecuredToken, { now: 1700000000 });
    expect(inspectResult.signatureVerified).toBe(false);
    expect(inspectResult.signature.verified).toBe(false);
    expect(inspectResult.signature.present).toBe(false);
    expect(inspectResult.warnings).toContain('Token specifies algorithm "none" (unsecured token)');
  });
});
