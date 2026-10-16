import { JwtParseError, ErrorCodes } from './errors.js';

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+={0,2}$/;

/**
 * Validates whether a string matches the Base64URL character set and structure.
 */
export function isValidBase64Url(str: string): boolean {
  if (typeof str !== 'string' || str.length === 0) {
    return false;
  }
  if (!BASE64URL_PATTERN.test(str)) {
    return false;
  }
  const unpadded = str.replace(/=+$/, '');
  return unpadded.length % 4 !== 1;
}

/**
 * Converts a Base64URL string to a Uint8Array.
 * Works seamlessly in both Node.js (18+) and modern browser environments.
 */
export function base64UrlToBytes(str: string): Uint8Array {
  if (typeof str !== 'string' || str.length === 0) {
    throw new JwtParseError('Base64URL segment cannot be empty', ErrorCodes.ERR_EMPTY_SEGMENT);
  }

  if (!BASE64URL_PATTERN.test(str)) {
    throw new JwtParseError(
      'Base64URL segment contains invalid characters',
      ErrorCodes.ERR_INVALID_BASE64URL
    );
  }

  const unpadded = str.replace(/=+$/, '');
  if (unpadded.length % 4 === 1) {
    throw new JwtParseError(
      'Base64URL segment has an invalid length (length mod 4 cannot equal 1)',
      ErrorCodes.ERR_INVALID_BASE64URL
    );
  }

  // Node.js Buffer fast-path if available
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(unpadded, 'base64url');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  // Web Standards / Browser fallback
  const base64 = unpadded.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLength);

  try {
    const binaryStr = atob(padded);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new JwtParseError(
      'Failed to decode Base64URL string',
      ErrorCodes.ERR_INVALID_BASE64URL
    );
  }
}

/**
 * Decodes a Base64URL-encoded UTF-8 string.
 * Strictly verifies UTF-8 byte sequences with fatal error checking.
 */
export function base64UrlDecode(str: string): string {
  const bytes = base64UrlToBytes(str);
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return decoder.decode(bytes);
  } catch {
    throw new JwtParseError(
      'Decoded Base64URL payload contains invalid UTF-8 byte sequences',
      ErrorCodes.ERR_INVALID_UTF8
    );
  }
}

/**
 * Encodes a string or Uint8Array into an unpadded Base64URL string.
 */
export function base64UrlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }

  // Browser / web fallback
  let binaryStr = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryStr += String.fromCharCode(bytes[i]!);
  }
  return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
