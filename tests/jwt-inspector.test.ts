import { describe, it, expect } from 'vitest';
import { inspectJwt, JwtParseError } from '../src/index.js';
import { createTestToken, createUnsecuredToken } from './helpers/test-tokens.js';

describe('jwt-inspector: inspectJwt', () => {
  const referenceTime = 1700000000; // 2023-11-14T22:13:20.000Z

  it('should inspect standard registered claims and produce formatted timestamp details', () => {
    const token = createTestToken(
      { alg: 'RS256', typ: 'JWT', kid: 'rsa-key-01' },
      {
        iss: 'https://issuer.example.com',
        sub: 'usr_98765',
        aud: ['api://backend', 'api://mobile'],
        jti: 'jwt_id_123',
        iat: referenceTime - 3600,
        nbf: referenceTime - 1800,
        exp: referenceTime + 3600,
        customClaim: 'myCustomValue',
      },
      'some_opaque_sig'
    );

    const result = inspectJwt(token, { now: referenceTime });

    expect(result.claims.alg).toBe('RS256');
    expect(result.claims.typ).toBe('JWT');
    expect(result.claims.kid).toBe('rsa-key-01');
    expect(result.claims.iss).toBe('https://issuer.example.com');
    expect(result.claims.sub).toBe('usr_98765');
    expect(result.claims.aud).toEqual(['api://backend', 'api://mobile']);
    expect(result.claims.jti).toBe('jwt_id_123');

    // Timestamps
    expect(result.claims.exp?.raw).toBe(referenceTime + 3600);
    expect(result.claims.exp?.iso).toBe('2023-11-14T23:13:20.000Z');
    expect(result.claims.exp?.date).toBeInstanceOf(Date);

    expect(result.claims.iat?.raw).toBe(referenceTime - 3600);
    expect(result.claims.iat?.iso).toBe('2023-11-14T21:13:20.000Z');

    expect(result.claims.nbf?.raw).toBe(referenceTime - 1800);
    expect(result.claims.nbf?.iso).toBe('2023-11-14T21:43:20.000Z');

    // Validity
    expect(result.validity.hasExpiration).toBe(true);
    expect(result.validity.isExpired).toBe(false);
    expect(result.validity.isNotYetValid).toBe(false);
    expect(result.validity.remainingValiditySeconds).toBe(3600);
    expect(result.validity.referenceTimeSeconds).toBe(referenceTime);

    // Custom claims preserved in payload
    expect(result.payload['customClaim']).toBe('myCustomValue');

    // Security flags
    expect(result.signatureVerified).toBe(false);
    expect(result.signature.verified).toBe(false);
    expect(result.signature.present).toBe(true);
    expect(result.signature.segment).toBe('some_opaque_sig');
  });

  it('should handle missing optional claims gracefully without errors', () => {
    const token = createTestToken({}, {});
    const result = inspectJwt(token, { now: referenceTime });

    expect(result.claims.iss).toBeUndefined();
    expect(result.claims.sub).toBeUndefined();
    expect(result.claims.aud).toBeUndefined();
    expect(result.claims.jti).toBeUndefined();
    expect(result.claims.exp).toBeNull();
    expect(result.claims.nbf).toBeNull();
    expect(result.claims.iat).toBeNull();

    expect(result.validity.hasExpiration).toBe(false);
    expect(result.validity.isExpired).toBeNull();
    expect(result.validity.isNotYetValid).toBeNull();
    expect(result.validity.remainingValiditySeconds).toBeNull();

    expect(result.warnings).toContain('Token does not specify an expiration (exp) claim');
  });

  it('should report expired status and negative remaining seconds when token is expired', () => {
    const token = createTestToken(undefined, {
      exp: referenceTime - 120, // Expired 2 minutes ago
    });

    const result = inspectJwt(token, { now: referenceTime });

    expect(result.validity.isExpired).toBe(true);
    expect(result.validity.remainingValiditySeconds).toBe(-120);
    expect(result.warnings).toContain('Token is expired');
  });

  it('should report not yet valid status when nbf is in future', () => {
    const token = createTestToken(undefined, {
      nbf: referenceTime + 300,
    });

    const result = inspectJwt(token, { now: referenceTime });

    expect(result.validity.isNotYetValid).toBe(true);
    expect(result.warnings).toContain('Token is not yet valid (nbf is in the future)');
  });

  it('should generate warnings for unsecured tokens with alg: "none"', () => {
    const token = createUnsecuredToken({ sub: 'user_1' });
    const result = inspectJwt(token);

    expect(result.claims.alg).toBe('none');
    expect(result.signature.present).toBe(false);
    expect(result.signature.verified).toBe(false);
    expect(result.warnings).toContain('Token specifies algorithm "none" (unsecured token)');
  });

  it('should produce warnings for malformed claim types instead of crashing', () => {
    const token = createTestToken(
      { alg: 123 },
      {
        iss: 456,
        sub: ['array_instead_of_string'],
        aud: 999,
        exp: 'not_a_numeric_date',
        nbf: true,
        iat: null,
      }
    );

    const result = inspectJwt(token, { now: referenceTime });

    expect(result.warnings).toContain('Header parameter "alg" is present but is not a string');
    expect(result.warnings).toContain('Claim "iss" is present but is not a string');
    expect(result.warnings).toContain('Claim "sub" is present but is not a string');
    expect(result.warnings).toContain('Claim "aud" is present but is not a valid string or string array');
    expect(result.warnings).toContain('Claim "exp" is present but is not a valid NumericDate (finite number)');
    expect(result.warnings).toContain('Claim "nbf" is present but is not a valid NumericDate (finite number)');
    expect(result.warnings).toContain('Claim "iat" is present but is not a valid NumericDate (finite number)');
  });

  it('should throw JwtParseError when the token structure is completely invalid', () => {
    expect(() => inspectJwt('malformed.token')).toThrowError(JwtParseError);
  });
});
