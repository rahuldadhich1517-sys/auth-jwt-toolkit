import { describe, it, expect } from 'vitest';
import { inspectJwt, JwtParseError } from '../src/index.js';
import {
  createTestToken,
  createUnsecuredToken,
  TEST_EPOCH,
} from './helpers/test-tokens.js';

describe('jwt-inspector: inspectJwt comprehensive test matrix', () => {
  const referenceTime = TEST_EPOCH; // 1700000000

  describe('A. Standard registered claims extraction', () => {
    it('faithfully extracts all standard registered claims with ISO timestamps and Date objects', () => {
      const token = createTestToken(
        { alg: 'RS256', typ: 'JWT', kid: 'rsa-key-42' },
        {
          iss: 'https://auth.company.com',
          sub: 'usr_admin_1',
          aud: ['api://billing', 'api://core'],
          jti: 'jwt_id_abcdef',
          exp: referenceTime + 3600,
          nbf: referenceTime - 1800,
          iat: referenceTime - 3600,
          customTenant: 'tenant_gold',
        },
        'mock_signature_data_abc'
      );

      const result = inspectJwt(token, { now: referenceTime });

      // Claims
      expect(result.claims.alg).toBe('RS256');
      expect(result.claims.typ).toBe('JWT');
      expect(result.claims.kid).toBe('rsa-key-42');
      expect(result.claims.iss).toBe('https://auth.company.com');
      expect(result.claims.sub).toBe('usr_admin_1');
      expect(result.claims.aud).toEqual(['api://billing', 'api://core']);
      expect(result.claims.jti).toBe('jwt_id_abcdef');

      // Timestamp details
      expect(result.claims.exp?.raw).toBe(referenceTime + 3600);
      expect(result.claims.exp?.iso).toBe('2023-11-14T23:13:20.000Z');
      expect(result.claims.exp?.date).toEqual(new Date((referenceTime + 3600) * 1000));

      expect(result.claims.nbf?.raw).toBe(referenceTime - 1800);
      expect(result.claims.nbf?.iso).toBe('2023-11-14T21:43:20.000Z');

      expect(result.claims.iat?.raw).toBe(referenceTime - 3600);
      expect(result.claims.iat?.iso).toBe('2023-11-14T21:13:20.000Z');

      // Validity
      expect(result.validity.hasExpiration).toBe(true);
      expect(result.validity.isExpired).toBe(false);
      expect(result.validity.isNotYetValid).toBe(false);
      expect(result.validity.remainingValiditySeconds).toBe(3600);
      expect(result.validity.referenceTimeSeconds).toBe(referenceTime);

      // Custom claim in payload
      expect(result.payload['customTenant']).toBe('tenant_gold');
    });

    it('handles single string audience claim in claims inspection', () => {
      const token = createTestToken(undefined, { aud: 'single-api' });
      const result = inspectJwt(token);
      expect(result.claims.aud).toBe('single-api');
    });

    it('leaves optional standard claims as undefined/null when not provided', () => {
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
  });

  describe('B. Header inspection & security warnings', () => {
    it('extracts alg, typ, kid and preserves additional custom header parameters', () => {
      const token = createTestToken(
        { alg: 'ES256', typ: 'JWT', kid: 'key-123', crit: ['b64'], customHeader: 'customVal' },
        { sub: 'usr_1' }
      );
      const result = inspectJwt(token);

      expect(result.claims.alg).toBe('ES256');
      expect(result.claims.typ).toBe('JWT');
      expect(result.claims.kid).toBe('key-123');
      expect(result.header['crit']).toEqual(['b64']);
      expect(result.header['customHeader']).toBe('customVal');
    });

    it('emits warning when alg is "none"', () => {
      const token = createUnsecuredToken({ sub: 'unsecured' });
      const result = inspectJwt(token);

      expect(result.claims.alg).toBe('none');
      expect(result.warnings).toContain('Token specifies algorithm "none" (unsecured token)');
    });

    it('supports unfamiliar or custom algorithm names without failing', () => {
      const token = createTestToken({ alg: 'CUSTOM-EXPERIMENTAL-ALG' }, { sub: 'usr_1' });
      const result = inspectJwt(token);

      expect(result.claims.alg).toBe('CUSTOM-EXPERIMENTAL-ALG');
    });

    it('emits warnings when header parameters alg, typ, or kid have incorrect types', () => {
      const token = createTestToken(
        { alg: 12345, typ: true, kid: ['not', 'a', 'string'] },
        { sub: 'usr_1' }
      );
      const result = inspectJwt(token);

      expect(result.claims.alg).toBeUndefined();
      expect(result.claims.typ).toBeUndefined();
      expect(result.claims.kid).toBeUndefined();
      expect(result.warnings).toContain('Header parameter "alg" is present but is not a string');
      expect(result.warnings).toContain('Header parameter "typ" is present but is not a string');
      expect(result.warnings).toContain('Header parameter "kid" is present but is not a string');
    });
  });

  describe('C. Expiration details and boundary states', () => {
    it('reports isExpired: false and positive remaining seconds for future expiration', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 600 });
      const result = inspectJwt(token, { now: referenceTime });

      expect(result.validity.hasExpiration).toBe(true);
      expect(result.validity.isExpired).toBe(false);
      expect(result.validity.remainingValiditySeconds).toBe(600);
      expect(result.warnings).not.toContain('Token is expired');
    });

    it('reports isExpired: true and negative remaining seconds for expired token', () => {
      const token = createTestToken(undefined, { exp: referenceTime - 120 });
      const result = inspectJwt(token, { now: referenceTime });

      expect(result.validity.hasExpiration).toBe(true);
      expect(result.validity.isExpired).toBe(true);
      expect(result.validity.remainingValiditySeconds).toBe(-120);
      expect(result.warnings).toContain('Token is expired');
    });

    it('reports isExpired: true and 0 remaining seconds at the exact expiration second', () => {
      const token = createTestToken(undefined, { exp: referenceTime });
      const result = inspectJwt(token, { now: referenceTime });

      expect(result.validity.isExpired).toBe(true);
      expect(result.validity.remainingValiditySeconds).toBe(0);
      expect(result.warnings).toContain('Token is expired');
    });

    it('reports isNotYetValid: true when nbf is in the future', () => {
      const token = createTestToken(undefined, { nbf: referenceTime + 300 });
      const result = inspectJwt(token, { now: referenceTime });

      expect(result.validity.isNotYetValid).toBe(true);
      expect(result.warnings).toContain('Token is not yet valid (nbf is in the future)');
    });

    it('honors clockToleranceSeconds in expiration and not-before calculations', () => {
      // Expired 5 seconds ago
      const token = createTestToken(undefined, {
        exp: referenceTime - 5,
        nbf: referenceTime + 5,
      });

      // Tolerance of 10s suppresses expired and notYetValid
      const result = inspectJwt(token, { now: referenceTime, clockToleranceSeconds: 10 });
      expect(result.validity.isExpired).toBe(false);
      expect(result.validity.isNotYetValid).toBe(false);
    });

    it('accepts Date instance for now reference time', () => {
      const token = createTestToken(undefined, { exp: referenceTime + 100 });
      const refDate = new Date(referenceTime * 1000);
      const result = inspectJwt(token, { now: refDate });

      expect(result.validity.remainingValiditySeconds).toBe(100);
      expect(result.validity.referenceTimeSeconds).toBe(referenceTime);
    });
  });

  describe('D. Malformed and partial data handling', () => {
    it('throws JwtParseError when the token syntax is completely malformed', () => {
      expect(() => inspectJwt('not.a-valid.jwt!')).toThrowError(JwtParseError);
      expect(() => inspectJwt('')).toThrowError(JwtParseError);
    });

    it('produces warnings for invalid claim types without crashing', () => {
      const token = createTestToken(undefined, {
        iss: 100,
        sub: ['not', 'a', 'string'],
        aud: 42,
        jti: true,
        exp: 'not_numeric',
        nbf: {},
        iat: [12345],
      });

      const result = inspectJwt(token, { now: referenceTime });

      expect(result.warnings).toContain('Claim "iss" is present but is not a string');
      expect(result.warnings).toContain('Claim "sub" is present but is not a string');
      expect(result.warnings).toContain('Claim "aud" is present but is not a valid string or string array');
      expect(result.warnings).toContain('Claim "jti" is present but is not a string');
      expect(result.warnings).toContain('Claim "exp" is present but is not a valid NumericDate (finite number)');
      expect(result.warnings).toContain('Claim "nbf" is present but is not a valid NumericDate (finite number)');
      expect(result.warnings).toContain('Claim "iat" is present but is not a valid NumericDate (finite number)');
    });

    it('warns when iat is in the future', () => {
      const token = createTestToken(undefined, { iat: referenceTime + 500 });
      const result = inspectJwt(token, { now: referenceTime });

      expect(result.warnings).toContain('Token "iat" (issued-at) timestamp is in the future');
    });
  });

  describe('E. Trust and privacy boundaries', () => {
    it('strictly guarantees signatureVerified and signature.verified are false', () => {
      const token = createTestToken(undefined, { sub: 'admin' }, 'valid_looking_signature');
      const result = inspectJwt(token);

      expect(result.signatureVerified).toBe(false);
      expect(result.signature.verified).toBe(false);
      expect(result.signature.present).toBe(true);
      expect(result.signature.segment).toBe('valid_looking_signature');
    });

    it('does not infer authentication or authorization merely from sub claim', () => {
      const token = createTestToken(undefined, { sub: 'root', roles: ['superuser'] });
      const result = inspectJwt(token);

      expect(result.claims.sub).toBe('root');
      expect(result.signatureVerified).toBe(false);
    });
  });
});
