# Changelog

All notable changes to `@rahul_dadhich15/auth-jwt-toolkit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-16

### Added

- **`decodeJwt(token, options?)`**: Decodes compact JWT tokens into typed header, payload, and signature segments with strict Base64URL and fatal UTF-8 validation.
- **`validateJwt(token, options?)`**: Validates JWT compact structure and claims (`exp`, `nbf`, `iat`, `iss`, `aud`, and custom required claims) with configurable clock tolerance and deterministic reference times, explicitly flagging `signatureVerified: false`.
- **`inspectJwt(token, options?)`**: Produces comprehensive inspection reports containing decoded header, payload, unverified signature status, standard registered claims with formatted ISO dates, validity states, remaining validity, and security warnings.
- **`getJwtExpiry(token, options?)`**: Extracts `exp` claim, converts to Date and ISO string, and calculates remaining validity in seconds without silently assuming infinite validity if absent.
- **`isJwtExpired(token, options?)`**: Evaluates expiration against reference time and clock tolerance, safely rejecting tokens missing `exp` by default.
- **`getJwtRemainingValidity(token, options?)`**: Returns remaining seconds until expiration, `0` at exact expiration second, negative seconds when expired, or `null` when no `exp` claim is present.
- **Typed Error Hierarchy**: `JwtToolkitError`, `JwtParseError`, and `JwtExpiryError` with detailed machine-readable `ErrorCodes`.
- **Zero Runtime Dependencies**: Completely dependency-free implementation targeting Node.js 18+ and modern browser/edge environments.
- **Dual Module Output**: Full ESM (`.js`) and CommonJS (`.cjs`) builds with bundled TypeScript declarations (`.d.ts` and `.d.cts`).
