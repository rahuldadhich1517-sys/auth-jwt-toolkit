# @rahul_dadhich15/auth-jwt-toolkit

[![CI](https://github.com/rahuldadhich1517-sys/auth-jwt-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/rahuldadhich1517-sys/auth-jwt-toolkit/actions)
[![npm version](https://img.shields.io/npm/v/@rahul_dadhich15/auth-jwt-toolkit.svg)](https://www.npmjs.com/package/@rahul_dadhich15/auth-jwt-toolkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)

A production-ready, lightweight, zero-dependency TypeScript toolkit for decoding, validating, inspecting, and checking the expiration of JSON Web Tokens (JWTs). Designed for both Node.js (18+) and modern browser / edge environments.

---

> [!CAUTION]
> ### Critical Security Disclaimer
>
> **Decoding a JWT does not verify its signature.** Do not use this package's decoded claims alone to authorize users, grant permissions, or make security-sensitive decisions. Verify the token with a trusted cryptographic JWT verification implementation (such as verifying signatures against public keys or shared secrets) before trusting its claims.
>
> This library is intentionally an **inspection, decoding, and claims-validation toolkit**, not a cryptographic verification engine. It never executes token content and always explicitly marks signatures as unverified (`signatureVerified: false`).

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [JWT Structure Explained](#jwt-structure-explained)
- [Core Utilities](#core-utilities)
  - [1. `decodeJwt(token, options?)`](#1-decodejwttoken-options)
  - [2. `validateJwt(token, options?)`](#2-validatejwttoken-options)
  - [3. `inspectJwt(token, options?)`](#3-inspectjwttoken-options)
  - [4. Expiry Utilities](#4-expiry-utilities)
    - [`getJwtExpiry(token, options?)`](#getjwtexpirytoken-options)
    - [`isJwtExpired(token, options?)`](#isjwtexpiredtoken-options)
    - [`getJwtRemainingValidity(token, options?)`](#getjwtremainingvaliditytoken-options)
- [Validation Options](#validation-options)
- [Standard Claims Reference](#standard-claims-reference)
- [Error Handling](#error-handling)
- [TypeScript Support & Generics](#typescript-support--generics)
- [Runtime Compatibility](#runtime-compatibility)
- [API Reference](#api-reference)
- [Security Boundaries & Limitations](#security-boundaries--limitations)
- [Development & Testing](#development--testing)
- [Project Architecture](#project-architecture)
- [License & Contributing](#license--contributing)

---

## Features

- **Zero Runtime Dependencies**: Pure TypeScript/JavaScript with zero external dependencies.
- **Strict Base64URL & UTF-8**: Strict character set checking and fatal UTF-8 byte decoding to prevent parser exploits and invalid replacements.
- **Unified Internal Parser**: Every utility shares a single, hardened parsing foundation with no code duplication.
- **RFC 7519 NumericDate Semantics**: Full compliance with RFC 7519 NumericDate specifications; strictly rejects string numbers, objects, booleans, and non-finite floats without silent coercion.
- **Safe Expiration Handling**: Exact expiration boundary accuracy (`currentTime >= exp` is expired). Missing expiration claims are never silently treated as infinitely valid.
- **Leeway & Deterministic Clocks**: Configurable clock tolerance (`clockToleranceSeconds`) and injectable reference time (`now`) for robust testing.
- **Universal Dual-Module Bundle**: Native ESM (`.js`) and CommonJS (`.cjs`) output with full TypeScript declarations (`.d.ts`, `.d.cts`).
- **DoS Guard**: Built-in configurable maximum token length protection (`maxTokenLength`).

---

## Installation

```bash
# npm
npm install @rahul_dadhich15/auth-jwt-toolkit

# pnpm
pnpm add @rahul_dadhich15/auth-jwt-toolkit

# yarn
yarn add @rahul_dadhich15/auth-jwt-toolkit
```

---

## Quick Start

```ts
import {
  decodeJwt,
  validateJwt,
  inspectJwt,
  isJwtExpired,
  getJwtRemainingValidity,
} from '@rahul_dadhich15/auth-jwt-toolkit';

const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxODAwMDAwMDAwfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

// 1. Decode
const decoded = decodeJwt(token);
console.log(decoded.payload); // { sub: "1234567890", name: "John Doe", exp: 1800000000 }

// 2. Validate claims
const validation = validateJwt(token, {
  requiredClaims: ['sub', 'name'],
  requireExpiration: true,
});
console.log(validation.valid); // true
console.log(validation.signatureVerified); // ALWAYS false (verification not performed)

// 3. Inspect metadata & validity
const inspection = inspectJwt(token);
console.log(inspection.validity.remainingValiditySeconds); // e.g. 100000

// 4. Expiry checks
console.log(isJwtExpired(token)); // false
console.log(getJwtRemainingValidity(token)); // remaining seconds
```

---

## JWT Structure Explained

A JSON Web Token (JWT) in compact serialization consists of three dot-separated (`.`) Base64URL-encoded parts:

```text
[Header].[Payload].[Signature]
```

1. **Header**: Contains metadata about the token format and cryptographic algorithms (e.g. `{"alg": "RS256", "typ": "JWT"}`).
2. **Payload**: Contains the claims (statements about the subject and application data).
3. **Signature**: Cryptographic signature generated by the issuer to ensure integrity.

> **Note**: An unsecured token (RFC 7519 § 6) has `alg: "none"` and an empty signature segment, formatted as `header.payload.`.

---

## Core Utilities

### 1. `decodeJwt(token, options?)`

Decodes a compact JWT string into its parsed JSON header, payload, and raw segments.

```ts
import { decodeJwt } from '@rahul_dadhich15/auth-jwt-toolkit';

interface UserPayload {
  sub: string;
  email: string;
  roles: string[];
}

const decoded = decodeJwt<Record<string, unknown>, UserPayload>(token);

console.log(decoded.header);    // { alg: "RS256", typ: "JWT" }
console.log(decoded.payload);   // UserPayload
console.log(decoded.signature); // Base64URL signature segment
console.log(decoded.segments);  // { header: "...", payload: "...", signature: "..." }
```

- **Throws**: `JwtParseError` if the token is not a string, empty, has segment count $\neq 3$, contains invalid Base64URL, contains invalid UTF-8, or contains non-object JSON.
- **Safety**: Never evaluates code (`eval` or `Function`) and never leaks token content in error messages.

### 2. `validateJwt(token, options?)`

Validates JWT syntax and selected claims without throwing for validation errors.

```ts
import { validateJwt } from '@rahul_dadhich15/auth-jwt-toolkit';

const result = validateJwt(token, {
  issuer: 'https://auth.example.com',
  audience: 'api://backend',
  requiredClaims: ['sub', 'tenant_id'],
  requireExpiration: true,
  clockToleranceSeconds: 30, // 30 seconds leeway
});

if (result.valid) {
  console.log('Token structure and claims are valid!');
  console.log('Signature verified:', result.signatureVerified); // false
} else {
  console.error('Validation errors:', result.errors);
  // Example: [{ code: "TOKEN_EXPIRED", message: "Token has expired", claim: "exp" }]
}
```

#### Result Shape (`JwtValidationResult`):

```ts
interface JwtValidationResult {
  readonly valid: boolean;              // true only if structure and claims passed
  readonly structureValid: boolean;     // true if syntax, Base64URL, JSON are valid
  readonly claimsValid: boolean;        // true if all configured claims rules passed
  readonly expired: boolean;            // true if token has exp and is expired
  readonly notYetValid: boolean;         // true if token has nbf and is in the future
  readonly signatureVerified: false;    // ALWAYS false
  readonly errors: readonly JwtValidationError[];
  readonly warnings: readonly string[];
}
```

### 3. `inspectJwt(token, options?)`

Provides an all-in-one structured inspection report for debugging, observability, logging, and administrative interfaces.

```ts
import { inspectJwt } from '@rahul_dadhich15/auth-jwt-toolkit';

const inspection = inspectJwt(token);

console.log('Algorithm:', inspection.claims.alg);
console.log('Issuer:', inspection.claims.iss);
console.log('Expiration Date:', inspection.claims.exp?.iso); // "2026-10-16T18:00:00.000Z"
console.log('Remaining seconds:', inspection.validity.remainingValiditySeconds);
console.log('Warnings:', inspection.warnings);
```

### 4. Expiry Utilities

#### `getJwtExpiry(token, options?)`

Extracts the `exp` claim, converts it to a JavaScript `Date` and ISO string, and calculates remaining validity.

```ts
import { getJwtExpiry } from '@rahul_dadhich15/auth-jwt-toolkit';

const expiry = getJwtExpiry(token);

if (expiry.hasExpiration) {
  console.log('Expires at:', expiry.iso);
  console.log('Remaining seconds:', expiry.remainingValiditySeconds);
  console.log('Is expired:', expiry.isExpired);
} else {
  console.log('Token does not specify an expiration claim');
}
```

#### `isJwtExpired(token, options?)`

Checks whether the token has expired based on reference time and optional clock tolerance.

```ts
import { isJwtExpired } from '@rahul_dadhich15/auth-jwt-toolkit';

// By default, throws JwtExpiryError if 'exp' is missing (prevents assuming infinite validity)
const expired = isJwtExpired(token);

// Custom tolerance and strategy for missing exp
const expiredWithOpts = isJwtExpired(token, {
  clockToleranceSeconds: 10,
  treatMissingExpAs: 'expired', // 'error' | 'expired' | 'not-expired'
});
```

#### `getJwtRemainingValidity(token, options?)`

Calculates remaining validity in seconds:
- **Positive number**: Token is valid for that many seconds.
- **`0`**: Token is expiring at the current instant.
- **Negative number**: Token is already expired by that many seconds.
- **`null`**: Token does not contain an `exp` claim.

```ts
import { getJwtRemainingValidity } from '@rahul_dadhich15/auth-jwt-toolkit';

const remainingSeconds = getJwtRemainingValidity(token);

if (remainingSeconds !== null && remainingSeconds < 300) {
  console.log('Token expires in less than 5 minutes! Triggering proactive refresh...');
}
```

---

## Validation Options

The `validateJwt` function supports the following configuration options:

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `requiredClaims` | `string[]` | `undefined` | Array of claim keys that must be present in payload. |
| `requireExpiration` | `boolean` | `false` | When true, requires `exp` to be present and valid. |
| `issuer` | `string \| string[]` | `undefined` | Expected issuer or allowed issuers (`iss` claim). |
| `audience` | `string \| string[]` | `undefined` | Expected audience or allowed audiences (`aud` claim). |
| `clockToleranceSeconds` | `number` | `0` | Leeway in seconds to compensate for server clock drift. |
| `now` | `Date \| number` | `Date.now()` | Reference time for deterministic testing. |
| `maxTokenLength` | `number` | `65536` (64 KB) | Maximum allowed token string length. |

---

## Standard Claims Reference

This library implements strict RFC 7519 and RFC 7515 registered claims handling:

| Claim | Full Name | Specification | Type Expected | Handling |
| :--- | :--- | :--- | :--- | :--- |
| `exp` | Expiration Time | RFC 7519 § 4.1.4 | `number` (NumericDate) | Expired if `currentTime >= exp + tolerance`. |
| `nbf` | Not Before | RFC 7519 § 4.1.5 | `number` (NumericDate) | Not yet valid if `currentTime < nbf - tolerance`. |
| `iat` | Issued At | RFC 7519 § 4.1.6 | `number` (NumericDate) | Emits warning if `iat > currentTime + tolerance`. |
| `iss` | Issuer | RFC 7519 § 4.1.1 | `string` | Matched against configured string/array. |
| `aud` | Audience | RFC 7519 § 4.1.3 | `string \| string[]` | Matched if any expected audience matches. |
| `sub` | Subject | RFC 7519 § 4.1.2 | `string` | Extracted and reported in inspection. |
| `jti` | JWT ID | RFC 7519 § 4.1.7 | `string` | Unique token identifier. |
| `alg` | Algorithm | RFC 7515 § 4.1.1 | `string` | Header parameter; warns if `alg: "none"`. |
| `typ` | Token Type | RFC 7515 § 4.1.9 | `string` | Header parameter (typically `"JWT"`). |
| `kid` | Key ID | RFC 7515 § 4.1.4 | `string` | Key identifier hint. |

---

## Error Handling

All thrown errors inherit from `JwtToolkitError` and provide a consistent `.code` property.

```ts
import { decodeJwt, JwtParseError, JwtExpiryError, ErrorCodes } from '@rahul_dadhich15/auth-jwt-toolkit';

try {
  decodeJwt('invalid-token');
} catch (error) {
  if (error instanceof JwtParseError) {
    console.error('Parse failure:', error.code, error.message);
    if (error.code === ErrorCodes.ERR_INVALID_SEGMENT_COUNT) {
      // Handle invalid segment structure
    }
  }
}
```

### Machine-Readable Error Codes:

- `ERR_INVALID_TOKEN_TYPE`: Token is not a string or is empty.
- `ERR_TOKEN_TOO_LARGE`: Token exceeds `maxTokenLength`.
- `ERR_INVALID_SEGMENT_COUNT`: Token does not contain exactly 3 dot-separated segments.
- `ERR_EMPTY_SEGMENT`: Header or payload segment is empty.
- `ERR_INVALID_BASE64URL`: Segment contains characters outside the Base64URL alphabet or bad length.
- `ERR_INVALID_UTF8`: Decoded bytes contain invalid UTF-8 byte sequences.
- `ERR_INVALID_JSON`: Segment is not valid JSON.
- `ERR_INVALID_JSON_OBJECT`: Segment JSON is a primitive or array instead of an object.
- `ERR_NO_EXPIRATION_CLAIM`: Token has no `exp` claim when checking expiration.
- `ERR_INVALID_EXPIRATION_CLAIM`: Claim `exp` is not a valid NumericDate.
- `ERR_INVALID_REFERENCE_TIME`: Injected `now` reference time is invalid.
- `ERR_INVALID_CLOCK_TOLERANCE`: Clock tolerance is negative or non-finite.

---

## TypeScript Support & Generics

Strongly typed with full generic support for both header and payload interfaces:

```ts
import { decodeJwt, inspectJwt } from '@rahul_dadhich15/auth-jwt-toolkit';

interface MyHeader {
  alg: 'RS256';
  kid: string;
}

interface MyPayload {
  sub: string;
  email: string;
  organizationId: string;
  roles: string[];
}

const decoded = decodeJwt<MyHeader, MyPayload>(token);

// Full IDE autocomplete and type safety
console.log(decoded.header.kid);
console.log(decoded.payload.organizationId);
```

---

## Runtime Compatibility

- **Node.js**: 18.0.0 or higher.
- **Browser**: Modern browsers supporting `TextDecoder` and `atob`/`btoa`.
- **Edge Runtimes**: Cloudflare Workers, Vercel Edge, Deno, Bun.
- **Zero Cryptographic Dependencies**: Does not require Node's `node:crypto` or WebCrypto APIs for decoding or inspection.

---

## API Reference

### Exported Functions

```ts
function decodeJwt<Header extends object = Record<string, unknown>, Payload extends object = Record<string, unknown>>(
  token: string,
  options?: DecodeJwtOptions
): DecodedJwt<Header, Payload>;

function validateJwt(
  token: string,
  options?: JwtValidatorOptions
): JwtValidationResult;

function inspectJwt<Header extends object = Record<string, unknown>, Payload extends object = Record<string, unknown>>(
  token: string,
  options?: JwtInspectorOptions
): JwtInspectionResult<Header, Payload>;

function getJwtExpiry(
  token: string,
  options?: GetJwtExpiryOptions
): JwtExpiryResult;

function isJwtExpired(
  token: string,
  options?: IsJwtExpiredOptions
): boolean;

function getJwtRemainingValidity(
  token: string,
  options?: GetJwtRemainingValidityOptions
): number | null;
```

---

## Security Boundaries & Limitations

1. **No Cryptographic Verification**: This library **does not verify signatures** or cryptographic keys. If you require cryptographic signature verification, use a dedicated crypto library (such as `jose` or `jsonwebtoken`) after or alongside this toolkit.
2. **Untrusted Data Notice**: Claims in a decoded token are readable data that may have been tampered with if the token was not verified against a trusted key. Never make authorization decisions solely based on decoded claims.
3. **No Network Access**: This library never connects to external servers, fetches remote JWKS (`jku`), or follows URLs.
4. **No Code Execution**: Claims are parsed strictly with `JSON.parse` and are never evaluated as JavaScript expressions.

---

## Development & Testing

```bash
# Install dependencies
npm install

# Run type checking
npm run typecheck

# Run test suite
npm run test:run

# Build ESM, CJS, and type definitions
npm run build

# Verify packaging
npm pack --dry-run
```

---

## Project Architecture

```text
auth-jwt-toolkit/
├── src/
│   ├── jwt-decoder/        # decodeJwt implementation and types
│   ├── jwt-validator/      # validateJwt implementation and types
│   ├── jwt-inspector/      # inspectJwt implementation and types
│   ├── jwt-expiry/         # getJwtExpiry, isJwtExpired, getJwtRemainingValidity
│   ├── internal/           # Shared token parser, Base64URL, time, claims, errors
│   └── index.ts            # Public barrel entry point
├── tests/
│   ├── jwt-decoder.test.ts
│   ├── jwt-validator.test.ts
│   ├── jwt-inspector.test.ts
│   ├── jwt-expiry.test.ts
│   ├── security.test.ts
│   └── integration.test.ts
├── .github/workflows/ci.yml
├── CHANGELOG.md
├── LICENSE
├── package.json
├── tsconfig.json
└── tsup.config.ts
```

---

## License & Contributing

Licensed under the [MIT License](LICENSE). Contributions, bug reports, and suggestions are welcome via [GitHub Issues](https://github.com/rahuldadhich1517-sys/auth-jwt-toolkit/issues).