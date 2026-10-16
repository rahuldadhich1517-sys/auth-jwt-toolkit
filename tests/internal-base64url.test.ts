import { describe, it, expect } from 'vitest';
import {
  isValidBase64Url,
  base64UrlToBytes,
  base64UrlDecode,
  base64UrlEncode,
} from '../src/internal/base64url.js';
import {
  isPlainObject,
  isNonEmptyString,
  normalizeAudience,
  extractTimestampClaim,
} from '../src/internal/claims.js';
import {
  isValidNumericDate,
  numericDateToDate,
  numericDateToIso,
  resolveReferenceTime,
  validateClockTolerance,
} from '../src/internal/time.js';
import { JwtParseError, JwtExpiryError } from '../src/index.js';

describe('internal: base64url utilities', () => {
  it('validates Base64URL string formats accurately', () => {
    expect(isValidBase64Url('')).toBe(false);
    expect(isValidBase64Url(null as unknown as string)).toBe(false);
    expect(isValidBase64Url(undefined as unknown as string)).toBe(false);
    expect(isValidBase64Url('abc+def')).toBe(false); // + is invalid in base64url
    expect(isValidBase64Url('abc/def')).toBe(false); // / is invalid in base64url
    expect(isValidBase64Url('a')).toBe(false); // length mod 4 == 1
    expect(isValidBase64Url('ab')).toBe(true);
    expect(isValidBase64Url('abc')).toBe(true);
    expect(isValidBase64Url('abcd')).toBe(true);
    expect(isValidBase64Url('ab==')).toBe(true);
  });

  it('rejects invalid inputs in base64UrlToBytes', () => {
    expect(() => base64UrlToBytes('')).toThrow(JwtParseError);
    expect(() => base64UrlToBytes(null as unknown as string)).toThrow(JwtParseError);
    expect(() => base64UrlToBytes('invalid+char')).toThrow(JwtParseError);
    expect(() => base64UrlToBytes('a')).toThrow(JwtParseError); // length mod 4 === 1
  });

  it('encodes and decodes utf-8 strings correctly', () => {
    const raw = 'Hello 🚀 World! 漢字';
    const encoded = base64UrlEncode(raw);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');

    const decoded = base64UrlDecode(encoded);
    expect(decoded).toBe(raw);
  });

  it('handles Uint8Array input in base64UrlEncode', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const encoded = base64UrlEncode(bytes);
    expect(base64UrlDecode(encoded)).toBe('Hello');
  });

  it('falls back to web standards / browser implementation when Buffer is undefined', () => {
    const originalBuffer = globalThis.Buffer;
    try {
      // Temporarily remove Buffer
      // @ts-expect-error Mocking browser environment
      delete globalThis.Buffer;

      const raw = 'Hello Browser World 🌍';
      const encoded = base64UrlEncode(raw);
      expect(encoded).toBeDefined();

      const decoded = base64UrlDecode(encoded);
      expect(decoded).toBe(raw);

      // Decoding byte conversion in browser fallback
      const bytes = base64UrlToBytes(encoded);
      expect(bytes).toBeInstanceOf(Uint8Array);

      // Test decoding error in browser fallback when atob fails
      const originalAtob = globalThis.atob;
      try {
        globalThis.atob = () => {
          throw new Error('Invalid character in atob');
        };
        expect(() => base64UrlToBytes('validSegment')).toThrow(JwtParseError);
      } finally {
        globalThis.atob = originalAtob;
      }
    } finally {
      globalThis.Buffer = originalBuffer;
    }
  });
});

describe('internal: claims utilities', () => {
  it('correctly identifies plain objects', () => {
    expect(isPlainObject({})).toBe(true);
    expect(isPlainObject({ a: 1 })).toBe(true);
    expect(isPlainObject(null)).toBe(false);
    expect(isPlainObject([])).toBe(false);
    expect(isPlainObject('string')).toBe(false);
    expect(isPlainObject(123)).toBe(false);
  });

  it('correctly identifies non-empty strings', () => {
    expect(isNonEmptyString('hello')).toBe(true);
    expect(isNonEmptyString('')).toBe(false);
    expect(isNonEmptyString('   ')).toBe(false);
    expect(isNonEmptyString(null)).toBe(false);
    expect(isNonEmptyString(123)).toBe(false);
  });

  it('normalizes audience claim correctly', () => {
    expect(normalizeAudience('aud-single')).toEqual(['aud-single']);
    expect(normalizeAudience(['aud-1', 'aud-2'])).toEqual(['aud-1', 'aud-2']);
    expect(normalizeAudience(['aud-1', 123])).toBeNull();
    expect(normalizeAudience(123)).toBeNull();
    expect(normalizeAudience({})).toBeNull();
    expect(normalizeAudience(null)).toBeNull();
  });

  it('extracts timestamp claim correctly and handles out of range dates', () => {
    const valid = extractTimestampClaim(1700000000);
    expect(valid).not.toBeNull();
    expect(valid?.raw).toBe(1700000000);
    expect(valid?.iso).toBe('2023-11-14T22:13:20.000Z');

    expect(extractTimestampClaim('not-a-number')).toBeNull();
    expect(extractTimestampClaim(NaN)).toBeNull();
    expect(extractTimestampClaim(Infinity)).toBeNull();

    // Out-of-range timestamp where toISOString throws RangeError
    const outOfRange = extractTimestampClaim(1e16);
    expect(outOfRange).toBeNull();
  });
});

describe('internal: time utilities', () => {
  it('validates numeric dates', () => {
    expect(isValidNumericDate(0)).toBe(true);
    expect(isValidNumericDate(-100)).toBe(true);
    expect(isValidNumericDate(1700000000.5)).toBe(true);
    expect(isValidNumericDate('1700000000')).toBe(false);
    expect(isValidNumericDate(NaN)).toBe(false);
    expect(isValidNumericDate(Infinity)).toBe(false);
    expect(isValidNumericDate(null)).toBe(false);
  });

  it('converts numeric date to Date and ISO string safely', () => {
    const date = numericDateToDate(1700000000);
    expect(date.getTime()).toBe(1700000000000);

    const iso = numericDateToIso(1700000000);
    expect(iso).toBe('2023-11-14T22:13:20.000Z');

    // Out-of-range timestamp
    expect(numericDateToIso(1e16)).toBeNull();
  });

  it('resolves reference time with Date, number, and rejects invalid inputs', () => {
    expect(resolveReferenceTime(1700000000)).toBe(1700000000);
    expect(resolveReferenceTime(1700000000000)).toBe(1700000000); // ms to sec
    expect(resolveReferenceTime(new Date(1700000000000))).toBe(1700000000);

    expect(() => resolveReferenceTime(new Date(NaN))).toThrow(JwtExpiryError);
    expect(() => resolveReferenceTime(NaN)).toThrow(JwtExpiryError);
    expect(() => resolveReferenceTime(Infinity)).toThrow(JwtExpiryError);
    expect(() => resolveReferenceTime('2023-11-14' as unknown as number)).toThrow(JwtExpiryError);
  });

  it('validates clock tolerance', () => {
    expect(validateClockTolerance(undefined)).toBe(0);
    expect(validateClockTolerance(60)).toBe(60);
    expect(validateClockTolerance(0)).toBe(0);
    expect(validateClockTolerance(0.5)).toBe(0.5);

    expect(() => validateClockTolerance(-1)).toThrow(JwtExpiryError);
    expect(() => validateClockTolerance(NaN)).toThrow(JwtExpiryError);
    expect(() => validateClockTolerance(Infinity)).toThrow(JwtExpiryError);
    expect(() => validateClockTolerance('60' as unknown as number)).toThrow(JwtExpiryError);
  });
});
