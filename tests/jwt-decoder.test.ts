import { describe, it, expect } from 'vitest';
import { decodeJwt, JwtParseError, ErrorCodes } from '../src/index.js';
import { createTestToken, createUnsecuredToken } from './helpers/test-tokens.js';

describe('jwt-decoder: decodeJwt', () => {
  it('should successfully decode a valid compact JWT', () => {
    const token = createTestToken(
      { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
      { sub: 'usr_abc123', role: 'admin', iat: 1700000000 },
      'mock_signature_segment'
    );

    const result = decodeJwt(token);

    expect(result.header).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'key-1' });
    expect(result.payload).toEqual({ sub: 'usr_abc123', role: 'admin', iat: 1700000000 });
    expect(result.signature).toBe('mock_signature_segment');
    expect(result.segments.signature).toBe('mock_signature_segment');
    expect(typeof result.segments.header).toBe('string');
    expect(typeof result.segments.payload).toBe('string');
  });

  it('should preserve TypeScript types with generic parameters', () => {
    interface CustomHeader {
      alg: string;
      kid: string;
    }
    interface CustomPayload {
      userId: string;
      permissions: string[];
    }

    const token = createTestToken(
      { alg: 'ES256', kid: 'key-42' },
      { userId: 'u-1', permissions: ['read', 'write'] }
    );

    const result = decodeJwt<CustomHeader, CustomPayload>(token);

    expect(result.header.kid).toBe('key-42');
    expect(result.payload.permissions).toContain('write');
  });

  it('should correctly handle Unicode, accents, and multi-byte characters', () => {
    const unicodePayload = {
      user: 'René François',
      bio: 'Developer 🚀 from 東京 and Москва',
      greeting: 'مرحبا بالعالم',
      symbols: '€, ¥, £, ©, ®, 𝄞',
    };

    const token = createTestToken(undefined, unicodePayload);
    const result = decodeJwt(token);

    expect(result.payload).toEqual(unicodePayload);
  });

  it('should correctly preserve nested objects, arrays, and primitive JSON types', () => {
    const complexPayload = {
      id: 42,
      active: true,
      score: 98.6,
      tags: ['jwt', 'security', 'auth'],
      metadata: {
        profile: {
          settings: {
            darkMode: true,
            theme: null,
          },
        },
      },
    };

    const token = createTestToken(undefined, complexPayload);
    const result = decodeJwt(token);

    expect(result.payload).toEqual(complexPayload);
  });

  it('should decode unsecured tokens with alg "none" and empty signature segment', () => {
    const token = createUnsecuredToken({ sub: 'unsecured_user' });
    const result = decodeJwt(token);

    expect(result.header).toEqual({ alg: 'none', typ: 'JWT' });
    expect(result.payload).toEqual({ sub: 'unsecured_user' });
    expect(result.signature).toBe('');
    expect(result.segments.signature).toBe('');
  });

  it('should throw when token is not a string at runtime', () => {
    // @ts-expect-error Testing runtime invalid types
    expect(() => decodeJwt(null)).toThrowError(JwtParseError);
    // @ts-expect-error Testing runtime invalid types
    expect(() => decodeJwt(undefined)).toThrowError(JwtParseError);
    // @ts-expect-error Testing runtime invalid types
    expect(() => decodeJwt(12345)).toThrowError(JwtParseError);
    // @ts-expect-error Testing runtime invalid types
    expect(() => decodeJwt({})).toThrowError(JwtParseError);
  });

  it('should throw ERR_INVALID_TOKEN_TYPE when token is empty', () => {
    expect(() => decodeJwt('')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_TOKEN_TYPE })
    );
  });

  it('should throw ERR_INVALID_SEGMENT_COUNT when token has fewer or more than 3 segments', () => {
    // 1 segment
    expect(() => decodeJwt('eyJhbGciOiJIUzI1NiJ9')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
    );

    // 2 segments
    expect(() => decodeJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
    );

    // 4 segments
    expect(() => decodeJwt('a.b.c.d')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
    );

    // 5 segments
    expect(() => decodeJwt('a.b.c.d.e')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_SEGMENT_COUNT })
    );
  });

  it('should throw ERR_EMPTY_SEGMENT when header or payload segment is empty', () => {
    // Empty header
    expect(() => decodeJwt('.eyJzdWIiOiIxMjMifQ.sig')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_EMPTY_SEGMENT })
    );

    // Empty payload
    expect(() => decodeJwt('eyJhbGciOiJIUzI1NiJ9..sig')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_EMPTY_SEGMENT })
    );
  });

  it('should throw ERR_INVALID_BASE64URL for invalid Base64URL characters', () => {
    // Invalid characters: space, exclamation mark, @, etc.
    expect(() => decodeJwt('eyJhbGci!OiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
    );

    expect(() => decodeJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig with space')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
    );
  });

  it('should throw ERR_INVALID_BASE64URL for invalid Base64URL length (length % 4 === 1)', () => {
    // 'a' has length 1, which cannot exist in valid Base64
    expect(() => decodeJwt('a.eyJzdWIiOiIxMjMifQ.sig')).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_BASE64URL })
    );
  });

  it('should throw ERR_INVALID_JSON when header or payload is not valid JSON', () => {
    const notJson = Buffer.from('hello world not json').toString('base64url');
    const validPart = Buffer.from('{"sub":"123"}').toString('base64url');

    expect(() => decodeJwt(`${notJson}.${validPart}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
    );

    expect(() => decodeJwt(`${validPart}.${notJson}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON })
    );
  });

  it('should throw ERR_INVALID_JSON_OBJECT when header or payload is valid JSON but not an object', () => {
    // Array instead of object
    const arrayPart = Buffer.from('[1, 2, 3]').toString('base64url');
    const validPart = Buffer.from('{"sub":"123"}').toString('base64url');

    expect(() => decodeJwt(`${arrayPart}.${validPart}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
    );

    expect(() => decodeJwt(`${validPart}.${arrayPart}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
    );

    // Primitive string instead of object
    const stringPart = Buffer.from('"plain string"').toString('base64url');
    expect(() => decodeJwt(`${validPart}.${stringPart}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
    );

    // Number instead of object
    const numberPart = Buffer.from('12345').toString('base64url');
    expect(() => decodeJwt(`${numberPart}.${validPart}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
    );

    // null instead of object
    const nullPart = Buffer.from('null').toString('base64url');
    expect(() => decodeJwt(`${validPart}.${nullPart}.sig`)).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_INVALID_JSON_OBJECT })
    );
  });

  it('should throw ERR_TOKEN_TOO_LARGE when token exceeds maxTokenLength', () => {
    const token = createTestToken();
    expect(() => decodeJwt(token, { maxTokenLength: 10 })).toThrowError(
      expect.objectContaining({ code: ErrorCodes.ERR_TOKEN_TOO_LARGE })
    );
  });

  it('should support large tokens within allowed limit', () => {
    const largeClaim = 'x'.repeat(10000);
    const token = createTestToken(undefined, { data: largeClaim });
    const result = decodeJwt(token, { maxTokenLength: 100000 });

    expect(result.payload['data']).toBe(largeClaim);
  });
});
