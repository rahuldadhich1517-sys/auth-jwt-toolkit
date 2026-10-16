import { describe, it, expect } from 'vitest';
import {
  decodeJwt,
  validateJwt,
  inspectJwt,
  getJwtExpiry,
  isJwtExpired,
  getJwtRemainingValidity,
} from '../src/index.js';
import { createTestToken } from './helpers/test-tokens.js';

describe('integration: real-world token workflows', () => {
  const referenceTime = 1700000000;

  it('Scenario 1: OpenID Connect (OIDC) ID Token validation & claims inspection', () => {
    // Realistic OIDC token payload
    const oidcHeader = { alg: 'RS256', typ: 'JWT', kid: 'oidc_rsa_2023' };
    const oidcPayload = {
      iss: 'https://auth.company.com/oauth2/v1',
      sub: 'google-oauth2|1098234789123',
      aud: 'https://api.company.com',
      exp: referenceTime + 3600,
      iat: referenceTime - 60,
      auth_time: referenceTime - 60,
      email: 'jane.dev@company.com',
      email_verified: true,
      name: 'Jane Developer',
      roles: ['engineer', 'admin'],
    };

    const token = createTestToken(
      oidcHeader,
      oidcPayload,
      'mock_crypto_signature_bytes_abc123'
    );

    // Step 1: Decode
    const decoded = decodeJwt<typeof oidcHeader, typeof oidcPayload>(token);
    expect(decoded.header.kid).toBe('oidc_rsa_2023');
    expect(decoded.payload.email).toBe('jane.dev@company.com');
    expect(decoded.payload.roles).toContain('admin');

    // Step 2: Validate structure and claims
    const validation = validateJwt(token, {
      issuer: 'https://auth.company.com/oauth2/v1',
      audience: 'https://api.company.com',
      requiredClaims: ['sub', 'email', 'roles'],
      requireExpiration: true,
      now: referenceTime,
    });

    expect(validation.valid).toBe(true);
    expect(validation.structureValid).toBe(true);
    expect(validation.claimsValid).toBe(true);
    expect(validation.signatureVerified).toBe(false);

    // Step 3: Inspect
    const inspection = inspectJwt(token, { now: referenceTime });
    expect(inspection.claims.iss).toBe('https://auth.company.com/oauth2/v1');
    expect(inspection.claims.sub).toBe('google-oauth2|1098234789123');
    expect(inspection.validity.isExpired).toBe(false);
    expect(inspection.validity.remainingValiditySeconds).toBe(3600);

    // Step 4: Expiry checking
    expect(isJwtExpired(token, { now: referenceTime })).toBe(false);
    expect(getJwtRemainingValidity(token, { now: referenceTime })).toBe(3600);
    const expiryInfo = getJwtExpiry(token, { now: referenceTime });
    expect(expiryInfo.hasExpiration).toBe(true);
    expect(expiryInfo.iso).toBe('2023-11-14T23:13:20.000Z');
  });

  it('Scenario 2: Proactive Token Refresh Strategy (evaluating validity window)', () => {
    // Token that has 120 seconds left before expiring
    const tokenExpiringSoon = createTestToken(undefined, {
      sub: 'usr_refresh_test',
      exp: referenceTime + 120,
    });

    const remaining = getJwtRemainingValidity(tokenExpiringSoon, { now: referenceTime });
    expect(remaining).toBe(120);

    // Refresh threshold: 300 seconds (5 minutes)
    const REFRESH_THRESHOLD_SECONDS = 300;
    const shouldRefreshToken = remaining !== null && remaining <= REFRESH_THRESHOLD_SECONDS;
    expect(shouldRefreshToken).toBe(true);

    // Token is not yet expired
    expect(isJwtExpired(tokenExpiringSoon, { now: referenceTime })).toBe(false);

    // Fast-forward 121 seconds: token is now expired
    const afterExpirationTime = referenceTime + 121;
    expect(isJwtExpired(tokenExpiringSoon, { now: afterExpirationTime })).toBe(true);
    expect(getJwtRemainingValidity(tokenExpiringSoon, { now: afterExpirationTime })).toBe(-1);
  });

  it('Scenario 3: Multi-tenant API Gateway claim routing and validation', () => {
    const multiTenantToken = createTestToken(undefined, {
      iss: 'https://auth.mycloud.io/realm/eu-west-1',
      aud: ['https://billing.mycloud.io', 'https://compute.mycloud.io'],
      exp: referenceTime + 7200,
      tenant_id: 'tenant_prod_7788',
      plan: 'enterprise',
    });

    // Allowed issuers and audiences for billing service
    const billingValidation = validateJwt(multiTenantToken, {
      issuer: [
        'https://auth.mycloud.io/realm/us-east-1',
        'https://auth.mycloud.io/realm/eu-west-1',
      ],
      audience: 'https://billing.mycloud.io',
      requiredClaims: ['tenant_id', 'plan'],
      now: referenceTime,
    });

    expect(billingValidation.valid).toBe(true);

    // Gateway inspection
    const inspection = inspectJwt(multiTenantToken, { now: referenceTime });
    expect(inspection.payload['tenant_id']).toBe('tenant_prod_7788');
    expect(inspection.payload['plan']).toBe('enterprise');
    expect(inspection.validity.remainingValiditySeconds).toBe(7200);
  });
});
