import { describe, it, expect } from 'vitest';
import { decodeJwt, ErrorCodes } from '../src/index.js';
import {
  createTestToken,
  createUnsecuredToken,
  encodeBase64UrlUnpadded,
  DEFAULT_MOCK_SIGNATURE,
} from './helpers/test-tokens.js';

describe('jwt-decoder: decodeJwt comprehensive test matrix', () => {
  describe('A. Valid tokens and payload structures', () => {
    it('decodes a minimal token with empty objects for header and payload', () => {
      const token = createTestToken({}, {});
      const result = decodeJwt(token);

      expect(result.header).toEqual({});
      expect(result.payload).toEqual({});
      expect(result.signature).toBe(DEFAULT_MOCK_SIGNATURE);
      expect(result.segments.signature).toBe(DEFAULT_MOCK_SIGNATURE);
    });

    it('decodes typical alg and typ header fields (RS256, ES256, EdDSA, HS256)', () => {
      const algs = ['HS256', 'RS256', 'ES256', 'EdDSA', 'PS512'];
      for (const alg of algs) {
        const token = createTestToken({ alg, typ: 'JWT', kid: `key-${alg}` });
        const result = decodeJwt(token);
        expect(result.header['alg']).toBe(alg);
        expect(result.header['typ']).toBe('JWT');
        expect(result.header['kid']).toBe(`key-${alg}`);
      }
    });

    it('decodes all standard registered claims faithfully', () => {
      const standardPayload = {
        iss: 'https://issuer.example.com',
        sub: 'usr_7890',
        aud: ['https://api.example.com', 'https://auth.example.com'],
        exp: 1800000000,
        nbf: 1700000000,
        iat: 1699999000,
        jti: 'unique-jwt-id-99',
      };
      const token = createTestToken(undefined, standardPayload);
      const result = decodeJwt(token);

      expect(result.payload).toEqual(standardPayload);
    });

    it('preserves boolean, numeric, null, and empty claims with exact types', () => {
      const variedPayload = {
        boolTrue: true,
        boolFalse: false,
        integerZero: 0,
        integerPos: 42,
        integerNeg: -99,
        floatVal: 3.1415926535,
        explicitNull: null,
        emptyString: '',
        emptyObject: {},
        emptyArray: [],
      };

      const token = createTestToken(undefined, variedPayload);
      const result = decodeJwt(token);

      expect(result.payload).toEqual(variedPayload);
      expect(result.payload['boolTrue']).toBe(true);
      expect(result.payload['boolFalse']).toBe(false);
      expect(result.payload['integerZero']).toBe(0);
      expect(result.payload['explicitNull']).toBeNull();
      expect(result.payload['emptyString']).toBe('');
      expect(result.payload['emptyObject']).toEqual({});
      expect(result.payload['emptyArray']).toEqual([]);
    });

    it('preserves deep nested objects and multidimensional arrays', () => {
      const nestedPayload = {
        org: {
          id: 'org_001',
          departments: [
            {
              name: 'Engineering',
              teams: ['Core', 'Platform', 'Security'],
              budgets: [1000, 2500.5, [10, 20]],
            },
          ],
        },
      };

      const token = createTestToken(undefined, nestedPayload);
      const result = decodeJwt(token);

      expect(result.payload).toEqual(nestedPayload);
    });

    it('preserves non-ASCII, accents, and international text without corruption', () => {
      const intlPayload = {
        german: 'Übergröße und Äpfel',
        french: 'Garçon, déjà vu à Noël où êtes-vous ?',
        spanish: 'El pingüino subió a la montaña rápido',
        nordic: 'Blåbærsyltetøy og smørbrød',
        greek: 'Καλημέρα κόσμε, επιστήμη και φιλοσοφία',
        cyrillic: 'Привет, мир! Защита информации и криптография',
        arabic: 'مرحبا بالعالم ومفتاح التشفير',
        hebrew: 'שלום עולם ואבטחת מידע',
        japanese: 'こんにちは世界、東京タワー',
        korean: '안녕하세요 세계, 보안 토큰',
        chinese: '你好世界，数字签名与令牌',
      };

      const token = createTestToken(undefined, intlPayload);
      const result = decodeJwt(token);

      expect(result.payload).toEqual(intlPayload);
    });

    it('preserves emoji and complex multi-byte characters', () => {
      const emojiPayload = {
        rocket: '🚀',
        family: '👨‍👩‍👧‍👦',
        flags: '🇺🇸 🇨🇦 🇩🇪 🇯🇵 🇮🇳',
        symbols: '𝄞 𝄢 ♾️ ⚛️ 🛡️',
        math: '∀x ∈ ℝ, x² ≥ 0',
      };

      const token = createTestToken(undefined, emojiPayload);
      const result = decodeJwt(token);

      expect(result.payload).toEqual(emojiPayload);
    });

    it('handles escaped quotes, backslashes, and special characters', () => {
      const escapedPayload = {
        quote: 'He said: "Hello, \\world\\"!',
        windowsPath: 'C:\\Program Files\\nodejs\\node.exe',
        regexStr: '^https:\\/\\/.*\\.example\\.com\\/?.*$',
        newlineAndTab: 'Line 1\nLine 2\tIndented',
      };

      const token = createTestToken(undefined, escapedPayload);
      const result = decodeJwt(token);

      expect(result.payload).toEqual(escapedPayload);
    });

    it('supports custom TypeScript generic interfaces without requiring index signatures', () => {
      interface CustomHeader {
        alg: string;
        kid: string;
      }
      interface CustomUser {
        id: string;
        email: string;
        roles: string[];
      }

      const token = createTestToken(
        { alg: 'ES384', kid: 'kid_test_1' },
        { id: 'usr_1', email: 'test@example.com', roles: ['admin'] }
      );

      const result = decodeJwt<CustomHeader, CustomUser>(token);
      expect(result.header.alg).toBe('ES384');
      expect(result.header.kid).toBe('kid_test_1');
      expect(result.payload.id).toBe('usr_1');
      expect(result.payload.roles).toContain('admin');
    });
  });

  describe('B. Token segment handling & structure contracts', () => {
    it('decodes unsecured token with alg: "none" and trailing dot', () => {
      const token = createUnsecuredToken({ sub: 'user_unsecured' });
      const result = decodeJwt(token);

      expect(result.header['alg']).toBe('none');
      expect(result.payload['sub']).toBe('user_unsecured');
      expect(result.signature).toBe('');
      expect(result.segments.signature).toBe('');
    });

    it('rejects tokens without dots (0 segments)', () => {
      expect(() => decodeJwt('nodotsinthisstring')).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
      );
    });

    it('rejects tokens with only one dot (2 segments)', () => {
      const twoSegments = `${encodeBase64UrlUnpadded('{"alg":"none"}')}.${encodeBase64UrlUnpadded('{"sub":"123"}')}`;
      expect(() => decodeJwt(twoSegments)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
      );
    });

    it('rejects tokens with more than two dots (4 or 5 segments)', () => {
      expect(() => decodeJwt('seg1.seg2.seg3.seg4')).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
      );
      expect(() => decodeJwt('seg1.seg2.seg3.seg4.seg5')).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
      );
    });

    it('rejects tokens with empty header segment', () => {
      const validPayload = encodeBase64UrlUnpadded('{"sub":"123"}');
      expect(() => decodeJwt(`.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_EMPTY_SEGMENT })
      );
    });

    it('rejects tokens with empty payload segment', () => {
      const validHeader = encodeBase64UrlUnpadded('{"alg":"HS256"}');
      expect(() => decodeJwt(`${validHeader}..sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_EMPTY_SEGMENT })
      );
    });

    it('rejects tokens with both empty header and empty payload', () => {
      expect(() => decodeJwt('..sig')).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_EMPTY_SEGMENT })
      );
      expect(() => decodeJwt('..')).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_EMPTY_SEGMENT })
      );
    });

    it('rejects tokens with extra whitespace around the token', () => {
      const token = createTestToken();
      expect(() => decodeJwt(` ${token}`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      expect(() => decodeJwt(`${token} `)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      expect(() => decodeJwt(`\n${token}`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      expect(() => decodeJwt(`${token}\n`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      expect(() => decodeJwt(`\t${token}\t`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
    });

    it('rejects tokens with leading/trailing whitespace inside segments', () => {
      const validHeader = encodeBase64UrlUnpadded('{"alg":"HS256"}');
      const validPayload = encodeBase64UrlUnpadded('{"sub":"123"}');

      expect(() => decodeJwt(` ${validHeader}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      expect(() => decodeJwt(`${validHeader}. ${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      expect(() => decodeJwt(`${validHeader}.${validPayload}. sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
    });
  });

  describe('C. Base64URL validation', () => {
    it('rejects standard Base64 characters (+ and /) that are not valid Base64URL', () => {
      const validPart = encodeBase64UrlUnpadded('{"alg":"HS256"}');
      // '+' is illegal in Base64URL (must be '-')
      expect(() => decodeJwt(`${validPart}.abc+def.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );

      // '/' is illegal in Base64URL (must be '_')
      expect(() => decodeJwt(`${validPart}.abc/def.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
    });

    it('rejects invalid symbols and punctuation in segments', () => {
      const validPart = encodeBase64UrlUnpadded('{"alg":"HS256"}');
      const invalidChars = ['@', '#', '$', '%', '^', '&', '*', '(', ')', '!', '?', '<', '>', '~', '`'];

      for (const char of invalidChars) {
        expect(() => decodeJwt(`${validPart}.abc${char}def.sig`)).toThrowError(
          expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
        );
      }
    });

    it('rejects impossible encoded lengths (length % 4 === 1)', () => {
      const validPart = encodeBase64UrlUnpadded('{"alg":"HS256"}');
      // Single character 'a' has length 1 (1 % 4 === 1, mathematically impossible in Base64)
      expect(() => decodeJwt(`${validPart}.a.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
      // 5 characters 'abcde' has length 5 (5 % 4 === 1)
      expect(() => decodeJwt(`${validPart}.abcde.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
    });

    it('rejects excessive padding (>2 equals signs)', () => {
      const validPart = encodeBase64UrlUnpadded('{"alg":"HS256"}');
      expect(() => decodeJwt(`${validPart}.AA===.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
      );
    });
  });

  describe('D. JSON and UTF-8 handling', () => {
    const validHeader = encodeBase64UrlUnpadded('{"alg":"HS256"}');
    const validPayload = encodeBase64UrlUnpadded('{"sub":"123"}');

    it('rejects invalid JSON syntax in header and payload', () => {
      const badJson = encodeBase64UrlUnpadded('{ unquotedKey: "value" }');
      expect(() => decodeJwt(`${badJson}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
      );
      expect(() => decodeJwt(`${validHeader}.${badJson}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
      );
    });

    it('rejects trailing garbage after otherwise valid JSON', () => {
      const trailingGarbage = encodeBase64UrlUnpadded('{"sub":"123"} trailing');
      expect(() => decodeJwt(`${validHeader}.${trailingGarbage}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
      );
    });

    it('rejects unclosed JSON strings and missing braces', () => {
      const unclosedString = encodeBase64UrlUnpadded('{"sub":"123');
      expect(() => decodeJwt(`${validHeader}.${unclosedString}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
      );

      const missingBrace = encodeBase64UrlUnpadded('"sub":"123"}');
      expect(() => decodeJwt(`${validHeader}.${missingBrace}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
      );
    });

    it('rejects non-object JSON values for header (string, array, number, boolean, null)', () => {
      const primitiveString = encodeBase64UrlUnpadded('"just a string"');
      const primitiveArray = encodeBase64UrlUnpadded('["alg", "HS256"]');
      const primitiveNumber = encodeBase64UrlUnpadded('12345');
      const primitiveBool = encodeBase64UrlUnpadded('true');
      const primitiveNull = encodeBase64UrlUnpadded('null');

      expect(() => decodeJwt(`${primitiveString}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${primitiveArray}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${primitiveNumber}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${primitiveBool}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${primitiveNull}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
    });

    it('rejects non-object JSON values for payload (string, array, number, boolean, null)', () => {
      const primitiveString = encodeBase64UrlUnpadded('"just a string"');
      const primitiveArray = encodeBase64UrlUnpadded('["sub", "123"]');
      const primitiveNumber = encodeBase64UrlUnpadded('99999');
      const primitiveBool = encodeBase64UrlUnpadded('false');
      const primitiveNull = encodeBase64UrlUnpadded('null');

      expect(() => decodeJwt(`${validHeader}.${primitiveString}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${validHeader}.${primitiveArray}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${validHeader}.${primitiveNumber}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${validHeader}.${primitiveBool}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
      expect(() => decodeJwt(`${validHeader}.${primitiveNull}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
      );
    });

    it('rejects invalid UTF-8 byte sequences with ERR_INVALID_UTF8', () => {
      // 0xFF 0xFF is an invalid UTF-8 sequence
      const invalidUtf8Bytes = new Uint8Array([0xff, 0xff, 0xaa, 0xbb]);
      const invalidB64Url = Buffer.from(invalidUtf8Bytes).toString('base64url');

      expect(() => decodeJwt(`${invalidB64Url}.${validPayload}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_UTF8 })
      );
      expect(() => decodeJwt(`${validHeader}.${invalidB64Url}.sig`)).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_UTF8 })
      );
    });
  });

  describe('E. Runtime inputs and token size boundaries', () => {
    it('throws ERR_INVALID_TOKEN_TYPE for non-string runtime inputs', () => {
      const invalidInputs: unknown[] = [
        null,
        undefined,
        12345,
        true,
        false,
        {},
        [],
        Symbol('token'),
        () => 'token',
      ];

      for (const input of invalidInputs) {
        // @ts-expect-error testing invalid runtime inputs
        expect(() => decodeJwt(input)).toThrowError(
          expect.objectContaining({ code: ErrorCodes.ERR_INVALID_TOKEN_TYPE })
        );
      }
    });

    it('throws ERR_INVALID_TOKEN_TYPE for empty string', () => {
      expect(() => decodeJwt('')).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_INVALID_TOKEN_TYPE })
      );
    });

    it('enforces exact boundary of maxTokenLength', () => {
      const token = createTestToken();
      const tokenLen = token.length;

      // Exactly at limit: passes
      expect(() => decodeJwt(token, { maxTokenLength: tokenLen })).not.toThrow();

      // Exactly 1 below token length: fails
      expect(() => decodeJwt(token, { maxTokenLength: tokenLen - 1 })).toThrowError(
        expect.objectContaining({ code: ErrorCodes.ERR_TOKEN_TOO_LARGE })
      );
    });

    it('handles very large valid tokens within supported limits', () => {
      const largePayload = {
        data: 'a'.repeat(30000),
      };
      const largeToken = createTestToken(undefined, largePayload);
      const result = decodeJwt(largeToken, { maxTokenLength: 100000 });

      expect(result.payload['data']).toHaveLength(30000);
    });
  });
});
