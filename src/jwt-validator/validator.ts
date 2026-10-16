import { parseJwtRaw, type ParsedJwt } from '../internal/token-parser.js';
import { JwtParseError } from '../internal/errors.js';
import {
  isValidNumericDate,
  resolveReferenceTime,
  validateClockTolerance,
} from '../internal/time.js';
import type {
  JwtValidatorOptions,
  JwtValidationError,
  JwtValidationResult,
} from './types.js';

/**
 * Validates the structure and selected claims of a JWT without verifying its cryptographic signature.
 *
 * Security notice:
 * `valid: true` confirms only that the configured structure and claims checks passed.
 * It NEVER implies that the token signature was verified or that the token is authentic.
 * Always verify the signature with a trusted cryptographic implementation before granting access.
 *
 * @param token The compact JWT string to validate.
 * @param options Validation criteria (e.g. required claims, issuer, audience, tolerance, reference time).
 * @returns A structured validation report including validation status, errors, and warnings.
 */
export function validateJwt(
  token: string,
  options: JwtValidatorOptions = {}
): JwtValidationResult {
  const errors: JwtValidationError[] = [];
  const warnings: string[] = [];

  // Parse reference time and clock tolerance safely
  let currentTime: number;
  try {
    currentTime = resolveReferenceTime(options.now);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid reference time';
    errors.push({ code: 'ERR_INVALID_REFERENCE_TIME', message });
    return {
      valid: false,
      structureValid: false,
      claimsValid: false,
      expired: false,
      notYetValid: false,
      signatureVerified: false,
      errors,
      warnings,
    };
  }

  let tolerance: number;
  try {
    tolerance = validateClockTolerance(options.clockToleranceSeconds);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid clock tolerance';
    errors.push({ code: 'ERR_INVALID_CLOCK_TOLERANCE', message });
    return {
      valid: false,
      structureValid: false,
      claimsValid: false,
      expired: false,
      notYetValid: false,
      signatureVerified: false,
      errors,
      warnings,
    };
  }

  // Attempt to parse token structure
  let parsed: ParsedJwt<Record<string, unknown>, Record<string, unknown>>;
  try {
    parsed = parseJwtRaw<Record<string, unknown>, Record<string, unknown>>(token, {
      maxTokenLength: options.maxTokenLength,
    });
  } catch (err) {
    const code = err instanceof JwtParseError ? err.code : 'MALFORMED_TOKEN';
    const message = err instanceof Error ? err.message : 'Token parsing failed';
    errors.push({ code, message });

    return {
      valid: false,
      structureValid: false,
      claimsValid: false,
      expired: false,
      notYetValid: false,
      signatureVerified: false,
      errors,
      warnings,
    };
  }

  // Structure is valid
  const structureValid = true;
  let expired = false;
  let notYetValid = false;

  const header = parsed.header;
  const payload = parsed.payload;

  // Header warnings
  if (header.alg === 'none') {
    warnings.push('Token specifies algorithm "none" (unsecured token)');
  }

  // 1. Required claims validation
  if (options.requiredClaims !== undefined) {
    if (!Array.isArray(options.requiredClaims) || !options.requiredClaims.every((c) => typeof c === 'string')) {
      errors.push({
        code: 'ERR_INVALID_OPTIONS',
        message: 'Option "requiredClaims" must be an array of strings',
      });
    } else if (options.requiredClaims.length > 0) {
      for (const claim of options.requiredClaims) {
        if (payload[claim] === undefined) {
          errors.push({
            code: 'MISSING_REQUIRED_CLAIM',
            message: `Required claim "${claim}" is missing`,
            claim,
          });
        }
      }
    }
  }

  // 2. Expiration requirement
  if (options.requireExpiration && payload.exp === undefined) {
    errors.push({
      code: 'MISSING_REQUIRED_CLAIM',
      message: 'Token is missing required expiration (exp) claim',
      claim: 'exp',
    });
  }

  // 3. Expiration claim (exp) validation
  if (payload.exp !== undefined) {
    if (!isValidNumericDate(payload.exp)) {
      errors.push({
        code: 'INVALID_CLAIM_TYPE',
        message: 'Claim "exp" must be a valid NumericDate (finite number)',
        claim: 'exp',
      });
    } else {
      // RFC 7519 § 4.1.4: current time MUST be before the expiration date/time
      if (currentTime >= payload.exp + tolerance) {
        expired = true;
        errors.push({
          code: 'TOKEN_EXPIRED',
          message: 'Token has expired',
          claim: 'exp',
        });
      }
    }
  } else if (!options.requireExpiration) {
    warnings.push('Token does not contain an "exp" (expiration) claim');
  }

  // 4. Not-before claim (nbf) validation
  if (payload.nbf !== undefined) {
    if (!isValidNumericDate(payload.nbf)) {
      errors.push({
        code: 'INVALID_CLAIM_TYPE',
        message: 'Claim "nbf" must be a valid NumericDate (finite number)',
        claim: 'nbf',
      });
    } else {
      // RFC 7519 § 4.1.5: current time MUST be after or equal to the not-before date/time
      if (currentTime < payload.nbf - tolerance) {
        notYetValid = true;
        errors.push({
          code: 'TOKEN_NOT_YET_VALID',
          message: 'Token is not yet valid (nbf is in the future)',
          claim: 'nbf',
        });
      }
    }
  }

  // 5. Issued-at claim (iat) validation
  if (payload.iat !== undefined) {
    if (!isValidNumericDate(payload.iat)) {
      errors.push({
        code: 'INVALID_CLAIM_TYPE',
        message: 'Claim "iat" must be a valid NumericDate (finite number)',
        claim: 'iat',
      });
    } else if (payload.iat > currentTime + tolerance) {
      warnings.push('Token "iat" (issued-at) timestamp is in the future');
    }
  }

  // 6. Issuer (iss) validation
  if (options.issuer !== undefined) {
    if (
      typeof options.issuer !== 'string' &&
      !(Array.isArray(options.issuer) && options.issuer.every((i) => typeof i === 'string'))
    ) {
      errors.push({
        code: 'ERR_INVALID_OPTIONS',
        message: 'Option "issuer" must be a string or array of strings',
      });
    } else {
      const allowedIssuers = Array.isArray(options.issuer)
        ? options.issuer
        : [options.issuer];

      if (payload.iss === undefined) {
        errors.push({
          code: 'MISSING_REQUIRED_CLAIM',
          message: 'Token is missing issuer (iss) claim',
          claim: 'iss',
        });
      } else if (typeof payload.iss !== 'string') {
        errors.push({
          code: 'INVALID_CLAIM_TYPE',
          message: 'Claim "iss" must be a string',
          claim: 'iss',
        });
      } else if (!allowedIssuers.includes(payload.iss)) {
        errors.push({
          code: 'ISSUER_MISMATCH',
          message: `Token issuer "${payload.iss}" does not match expected issuer(s)`,
          claim: 'iss',
        });
      }
    }
  }

  // 7. Audience (aud) validation
  if (options.audience !== undefined) {
    if (
      typeof options.audience !== 'string' &&
      !(Array.isArray(options.audience) && options.audience.every((a) => typeof a === 'string'))
    ) {
      errors.push({
        code: 'ERR_INVALID_OPTIONS',
        message: 'Option "audience" must be a string or array of strings',
      });
    } else {
      const expectedAudiences = Array.isArray(options.audience)
        ? options.audience
        : [options.audience];

      const aud = payload.aud;
      if (aud === undefined) {
        errors.push({
          code: 'MISSING_REQUIRED_CLAIM',
          message: 'Token is missing audience (aud) claim',
          claim: 'aud',
        });
      } else if (typeof aud === 'string') {
        if (!expectedAudiences.includes(aud)) {
          errors.push({
            code: 'AUDIENCE_MISMATCH',
            message: `Token audience "${aud}" does not match expected audience(s)`,
            claim: 'aud',
          });
        }
      } else if (Array.isArray(aud)) {
        const isStringArray = aud.every((item) => typeof item === 'string');
        if (!isStringArray) {
          errors.push({
            code: 'INVALID_CLAIM_TYPE',
            message: 'Claim "aud" must be a string or array of strings',
            claim: 'aud',
          });
        } else {
          const matches = aud.some((item) => expectedAudiences.includes(item));
          if (!matches) {
            errors.push({
              code: 'AUDIENCE_MISMATCH',
              message: 'None of the token audiences match expected audience(s)',
              claim: 'aud',
            });
          }
        }
      } else {
        errors.push({
          code: 'INVALID_CLAIM_TYPE',
          message: 'Claim "aud" must be a string or array of strings',
          claim: 'aud',
        });
      }
    }
  }

  const claimsValid = errors.length === 0;
  const valid = structureValid && claimsValid;

  return {
    valid,
    structureValid,
    claimsValid,
    expired,
    notYetValid,
    signatureVerified: false,
    errors,
    warnings,
  };
}
