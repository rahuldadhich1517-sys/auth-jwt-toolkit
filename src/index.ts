// Core utilities
export { decodeJwt } from './jwt-decoder/index.js';
export type { DecodedJwt, DecodeJwtOptions } from './jwt-decoder/index.js';

export { validateJwt } from './jwt-validator/index.js';
export type {
  JwtValidatorOptions,
  JwtValidationError,
  JwtValidationResult,
} from './jwt-validator/index.js';

export { inspectJwt } from './jwt-inspector/index.js';
export type {
  JwtInspectorOptions,
  JwtInspectionResult,
  JwtHeaderSummary,
  JwtStandardClaims,
  JwtValiditySummary,
  JwtSignatureInfo,
} from './jwt-inspector/index.js';

export {
  getJwtExpiry,
  isJwtExpired,
  getJwtRemainingValidity,
} from './jwt-expiry/index.js';
export type {
  GetJwtExpiryOptions,
  JwtExpiryResult,
  IsJwtExpiredOptions,
  GetJwtRemainingValidityOptions,
} from './jwt-expiry/index.js';

// Errors and Error Codes
export {
  JwtToolkitError,
  JwtParseError,
  JwtExpiryError,
  ErrorCodes,
} from './internal/errors.js';
export type { ErrorCode } from './internal/errors.js';

// Timestamp Claim detail type
export type { TimestampClaimDetail } from './internal/claims.js';
