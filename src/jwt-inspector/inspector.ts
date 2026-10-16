import { parseJwtRaw } from '../internal/token-parser.js';
import {
  resolveReferenceTime,
  validateClockTolerance,
} from '../internal/time.js';
import { extractTimestampClaim, normalizeAudience } from '../internal/claims.js';
import type {
  JwtInspectorOptions,
  JwtInspectionResult,
  JwtStandardClaims,
  JwtValiditySummary,
  JwtSignatureInfo,
} from './types.js';

/**
 * Inspects a JWT and produces a comprehensive, structured overview of its
 * header, payload, claims, expiration status, and signature metadata.
 *
 * Security notice:
 * `inspectJwt` decodes the token and provides metadata for debugging, logging, and inspection.
 * It DOES NOT verify the signature or establish trust in any claims.
 *
 * @param token The compact JWT string to inspect.
 * @param options Reference time and clock tolerance options.
 * @returns A detailed inspection overview.
 * @throws {JwtParseError} When the token structure is invalid or malformed.
 */
export function inspectJwt<
  Header extends object = Record<string, unknown>,
  Payload extends object = Record<string, unknown>
>(token: string, options: JwtInspectorOptions = {}): JwtInspectionResult<Header, Payload> {
  const parsed = parseJwtRaw<Header, Payload>(token, {
    maxTokenLength: options.maxTokenLength,
  });

  const currentTime = resolveReferenceTime(options.now);
  const tolerance = validateClockTolerance(options.clockToleranceSeconds);

  const header = parsed.header;
  const payload = parsed.payload;
  const headerRecord = header as Record<string, unknown>;
  const payloadRecord = payload as Record<string, unknown>;
  const warnings: string[] = [];

  // Inspect Header
  const alg = typeof headerRecord['alg'] === 'string' ? headerRecord['alg'] : undefined;
  const typ = typeof headerRecord['typ'] === 'string' ? headerRecord['typ'] : undefined;
  const kid = typeof headerRecord['kid'] === 'string' ? headerRecord['kid'] : undefined;

  if (headerRecord['alg'] === 'none') {
    warnings.push('Token specifies algorithm "none" (unsecured token)');
  }
  if (headerRecord['alg'] !== undefined && typeof headerRecord['alg'] !== 'string') {
    warnings.push('Header parameter "alg" is present but is not a string');
  }

  // Inspect Payload Standard Claims
  const iss = typeof payloadRecord['iss'] === 'string' ? payloadRecord['iss'] : undefined;
  if (payloadRecord['iss'] !== undefined && typeof payloadRecord['iss'] !== 'string') {
    warnings.push('Claim "iss" is present but is not a string');
  }

  const sub = typeof payloadRecord['sub'] === 'string' ? payloadRecord['sub'] : undefined;
  if (payloadRecord['sub'] !== undefined && typeof payloadRecord['sub'] !== 'string') {
    warnings.push('Claim "sub" is present but is not a string');
  }

  const jti = typeof payloadRecord['jti'] === 'string' ? payloadRecord['jti'] : undefined;
  if (payloadRecord['jti'] !== undefined && typeof payloadRecord['jti'] !== 'string') {
    warnings.push('Claim "jti" is present but is not a string');
  }

  let aud: string | string[] | undefined;
  if (payloadRecord['aud'] !== undefined) {
    const normalizedAud = normalizeAudience(payloadRecord['aud']);
    if (normalizedAud === null) {
      warnings.push('Claim "aud" is present but is not a valid string or string array');
    } else {
      aud = typeof payloadRecord['aud'] === 'string' ? payloadRecord['aud'] : normalizedAud;
    }
  }

  // Timestamp claims
  let expDetail = null;
  if (payloadRecord['exp'] !== undefined) {
    expDetail = extractTimestampClaim(payloadRecord['exp']);
    if (expDetail === null) {
      warnings.push('Claim "exp" is present but is not a valid NumericDate (finite number)');
    }
  } else {
    warnings.push('Token does not specify an expiration (exp) claim');
  }

  let nbfDetail = null;
  if (payloadRecord['nbf'] !== undefined) {
    nbfDetail = extractTimestampClaim(payloadRecord['nbf']);
    if (nbfDetail === null) {
      warnings.push('Claim "nbf" is present but is not a valid NumericDate (finite number)');
    }
  }

  let iatDetail = null;
  if (payloadRecord['iat'] !== undefined) {
    iatDetail = extractTimestampClaim(payloadRecord['iat']);
    if (iatDetail === null) {
      warnings.push('Claim "iat" is present but is not a valid NumericDate (finite number)');
    } else if (iatDetail.raw > currentTime + tolerance) {
      warnings.push('Token "iat" (issued-at) timestamp is in the future');
    }
  }

  // Validity summary
  const hasExpiration = expDetail !== null;
  let isExpired: boolean | null = null;
  let remainingValiditySeconds: number | null = null;

  if (hasExpiration && expDetail) {
    isExpired = currentTime >= expDetail.raw + tolerance;
    remainingValiditySeconds = Math.floor(expDetail.raw - currentTime);
    if (isExpired) {
      warnings.push('Token is expired');
    }
  }

  let isNotYetValid: boolean | null = null;
  if (nbfDetail !== null) {
    isNotYetValid = currentTime < nbfDetail.raw - tolerance;
    if (isNotYetValid) {
      warnings.push('Token is not yet valid (nbf is in the future)');
    }
  }

  const claims: JwtStandardClaims = {
    alg,
    typ,
    kid,
    iss,
    sub,
    aud,
    jti,
    exp: expDetail,
    nbf: nbfDetail,
    iat: iatDetail,
  };

  const validity: JwtValiditySummary = {
    hasExpiration,
    isExpired,
    isNotYetValid,
    remainingValiditySeconds,
    referenceTimeSeconds: currentTime,
  };

  const signature: JwtSignatureInfo = {
    segment: parsed.signature,
    present: parsed.signature.length > 0,
    verified: false,
  };

  return {
    header,
    payload,
    signature,
    claims,
    validity,
    signatureVerified: false,
    warnings,
  };
}
