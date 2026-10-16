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
  type JwtValidationResult,
} from '../src/index.js';
import { createTestToken, encodeBase64UrlUnpadded } from './helpers/test-tokens.js';

// Deterministic Mulberry32 PRNG
function createPrng(seed: number) {
  let s = seed >>> 0;
  return function next(): number {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('property-based and deterministic fuzz testing', () => {
  const SEED = 0xbeefcafe;

  describe('Property 1: Round-trip Invariance', () => {
    it('preserves header and payload content across encode and decode for arbitrary JSON structures', () => {
      const prng = createPrng(SEED);

      const sampleKeys = ['sub', 'iss', 'roles', 'meta', 'score', 'active', 'tags', 'custom'];
      const sampleUnicode = ['Alpha', 'βeta', '漢字', '🚀', 'Привет', 'Café', 'Line\nBreak', 'Quote"Here'];

      for (let iteration = 0; iteration < 50; iteration++) {
        const header: Record<string, unknown> = {
          alg: prng() > 0.5 ? 'HS256' : 'RS256',
          typ: 'JWT',
          kid: `key-${Math.floor(prng() * 1000)}`,
        };

        const payload: Record<string, unknown> = {
          iat: 1700000000 + Math.floor(prng() * 10000),
          exp: 1700000000 + 20000 + Math.floor(prng() * 10000),
        };

        // Add 3-6 random claims
        const claimCount = 3 + Math.floor(prng() * 4);
        for (let c = 0; c < claimCount; c++) {
          const key = sampleKeys[Math.floor(prng() * sampleKeys.length)] + `_${c}`;
          const valType = Math.floor(prng() * 6);
          switch (valType) {
            case 0:
              payload[key] = sampleUnicode[Math.floor(prng() * sampleUnicode.length)];
              break;
            case 1:
              payload[key] = Math.floor(prng() * 100000) - 50000;
              break;
            case 2:
              payload[key] = prng() > 0.5;
              break;
            case 3:
              payload[key] = null;
              break;
            case 4:
              payload[key] = [1, 2, 'three', false];
              break;
            case 5:
              payload[key] = { nestedKey: 'nestedVal', count: iteration };
              break;
          }
        }

        const token = createTestToken(header, payload);
        const decoded = decodeJwt(token);

        expect(decoded.header).toEqual(header);
        expect(decoded.payload).toEqual(payload);
      }
    });
  });

  describe('Property 2: Signature Isolation', () => {
    it('never affects header or payload parsing when signature segment changes', () => {
      const fixedHeader = { alg: 'HS256', typ: 'JWT' };
      const fixedPayload = { sub: 'usr_invariant', exp: 1800000000 };

      const baseToken = createTestToken(
        fixedHeader,
        fixedPayload,
        encodeBase64UrlUnpadded('initial_signature')
      );
      const baseDecoded = decodeJwt(baseToken);

      const mutatedSignatures = [
        '',
        encodeBase64UrlUnpadded('different_sig_123'),
        encodeBase64UrlUnpadded('random-byte-signature-bytes'),
        'a'.repeat(64),
        '__--__--',
      ];

      for (const newSig of mutatedSignatures) {
        const mutatedToken = createTestToken(fixedHeader, fixedPayload, newSig);

        const decoded = decodeJwt(mutatedToken);
        expect(decoded.header).toEqual(baseDecoded.header);
        expect(decoded.payload).toEqual(baseDecoded.payload);
        expect(decoded.signature).toBe(newSig);
        expect(decoded.segments.signature).toBe(newSig);

        // Validation of claims should be unaffected
        const valResult = validateJwt(mutatedToken, { now: 1700000000 });
        expect(valResult.claimsValid).toBe(true);
        expect(valResult.signatureVerified).toBe(false);

        // Expiry should be unaffected
        const remaining = getJwtRemainingValidity(mutatedToken, { now: 1700000000 });
        expect(remaining).toBe(100000000);
      }
    });
  });

  describe('Property 3: Fuzz Robustness & Crash Immunity', () => {
    it('gracefully handles 200 random mutations without uncaught exceptions', () => {
      const prng = createPrng(SEED + 2);
      const seedToken = createTestToken(
        { alg: 'ES256', typ: 'JWT', kid: 'k1' },
        { sub: 'usr_fuzz', iss: 'auth', exp: 1750000000, nbf: 1650000000 }
      );

      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_./@#$%^&*() \t\n';

      for (let i = 0; i < 200; i++) {
        // Apply random mutation to the token
        let mutated = seedToken;
        const mutationType = Math.floor(prng() * 6);

        switch (mutationType) {
          case 0: {
            // Single char replacement
            const pos = Math.floor(prng() * mutated.length);
            const char = alphabet[Math.floor(prng() * alphabet.length)];
            mutated = mutated.slice(0, pos) + char + mutated.slice(pos + 1);
            break;
          }
          case 1: {
            // Insertion of random substring
            const pos = Math.floor(prng() * mutated.length);
            const insert = alphabet[Math.floor(prng() * alphabet.length)];
            mutated = mutated.slice(0, pos) + insert + mutated.slice(pos);
            break;
          }
          case 2: {
            // Deletion of random char
            if (mutated.length > 2) {
              const pos = Math.floor(prng() * mutated.length);
              mutated = mutated.slice(0, pos) + mutated.slice(pos + 1);
            }
            break;
          }
          case 3: {
            // Swapping or injecting dots
            const pos = Math.floor(prng() * mutated.length);
            mutated = mutated.slice(0, pos) + '.' + mutated.slice(pos);
            break;
          }
          case 4: {
            // Truncation
            const len = Math.floor(prng() * mutated.length);
            mutated = mutated.slice(0, len);
            break;
          }
          case 5: {
            // Completely random string
            const len = 5 + Math.floor(prng() * 50);
            mutated = Array.from({ length: len }, () => alphabet[Math.floor(prng() * alphabet.length)]).join('');
            break;
          }
        }

        // Test 1: validateJwt must never throw an uncaught error
        let valResult: JwtValidationResult | undefined;
        expect(() => {
          valResult = validateJwt(mutated, { now: 1700000000 });
        }).not.toThrow();
        expect(typeof valResult?.valid).toBe('boolean');
        expect(Array.isArray(valResult?.errors)).toBe(true);

        // Test 2: inspectJwt must only throw JwtParseError or JwtExpiryError if it throws
        try {
          const inspectRes = inspectJwt(mutated, { now: 1700000000 });
          expect(typeof inspectRes).toBe('object');
        } catch (err) {
          expect(err instanceof JwtParseError || err instanceof JwtExpiryError).toBe(true);
        }

        // Test 3: decodeJwt must ONLY throw JwtParseError if it throws
        try {
          decodeJwt(mutated);
        } catch (err) {
          expect(err).toBeInstanceOf(JwtParseError);
        }

        // Test 4: getJwtExpiry must ONLY throw JwtParseError or JwtExpiryError if it throws
        try {
          getJwtExpiry(mutated, { now: 1700000000 });
        } catch (err) {
          expect(err instanceof JwtParseError || err instanceof JwtExpiryError).toBe(true);
        }

        // Test 5: isJwtExpired must ONLY throw JwtParseError or JwtExpiryError if it throws
        try {
          isJwtExpired(mutated, { now: 1700000000 });
        } catch (err) {
          expect(err instanceof JwtParseError || err instanceof JwtExpiryError).toBe(true);
        }

        // Test 6: getJwtRemainingValidity must ONLY throw JwtParseError or JwtExpiryError if it throws
        try {
          getJwtRemainingValidity(mutated, { now: 1700000000 });
        } catch (err) {
          expect(err instanceof JwtParseError || err instanceof JwtExpiryError).toBe(true);
        }
      }
    });
  });

  describe('Property 4: Monotonic Remaining Validity Duration', () => {
    it('decreases remainingSeconds strictly monotonically with advancing reference time', () => {
      const token = createTestToken(undefined, { exp: 1700005000 });

      let lastRemaining = Infinity;
      for (let t = 1700000000; t <= 1700005000; t += 500) {
        const remaining = getJwtRemainingValidity(token, { now: t });
        expect(typeof remaining).toBe('number');
        expect(remaining).toBe(1700005000 - t);
        expect(remaining!).toBeLessThan(lastRemaining);
        lastRemaining = remaining!;
      }
    });
  });

  describe('Property 5: Clock Tolerance Monotonicity', () => {
    it('restores validity monotonically as clock tolerance exceeds expiration delta', () => {
      const exp = 1700000000;
      const token = createTestToken(undefined, { exp });
      const now = exp + 30; // Expired 30 seconds ago

      // Tolerance <= 30 must be invalid (since at tolerance 30, now >= exp + tolerance holds)
      for (const tol of [0, 5, 15, 29, 30]) {
        const res = validateJwt(token, { now, clockToleranceSeconds: tol });
        expect(res.valid).toBe(false);
        expect(res.expired).toBe(true);
      }

      // Tolerance > 30 must be valid
      for (const tol of [31, 35, 60, 120]) {
        const res = validateJwt(token, { now, clockToleranceSeconds: tol });
        expect(res.valid).toBe(true);
        expect(res.expired).toBe(false);
      }
    });
  });
});
