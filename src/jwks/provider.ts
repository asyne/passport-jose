import * as jose from 'jose';

import { SecretOrKeyProvider } from '../types';

/**
 * Creates a SecretOrKeyProvider that fetches public keys from a remote JWKS endpoint.
 *
 * This function provides integration with JSON Web Key Set (JWKS) endpoints for
 * dynamic public key resolution. It's particularly useful for scenarios where:
 * - Public keys rotate frequently
 * - Multiple issuers are supported
 * - Keys are managed by external identity providers (Auth0, AWS Cognito, etc.)
 *
 * @param jwksUri - The URI of the JWKS endpoint (must be a valid HTTPS URL)
 * @param options - Configuration options for the remote JWKS client
 * @param options.timeoutDuration - Request timeout in milliseconds (default: 5000)
 * @param options.cooldownDuration - Cooldown period between requests in milliseconds (default: 30000)
 * @param options.cacheMaxAge - Maximum cache age for JWKS in milliseconds (default: 600000)
 * @param options.jwksRequestsPerMinute - Rate limit for JWKS requests (default: 5)
 * @param options.jwksRequestTimeout - Timeout for individual JWKS requests (default: 5000)
 * @param options.agent - HTTP agent for making requests
 * @param options.headers - Additional headers to include in JWKS requests
 *
 * @returns A SecretOrKeyProvider function compatible with passport-jose Strategy
 *
 * @example
 * ```typescript
 * import { Strategy, ExtractJwt, fromRemoteJwks } from 'passport-jose';
 *
 * const jwksProvider = fromRemoteJwks('https://your-domain.auth0.com/.well-known/jwks.json', {
 *   timeoutDuration: 10000,
 *   cacheMaxAge: 300000,
 * });
 *
 * passport.use(new Strategy({
 *   jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
 *   withKeyProvider: jwksProvider,
 *   algorithms: ['RS256'],
 *   issuer: 'https://your-domain.auth0.com/',
 *   audience: 'your-api-identifier'
 * }, (payload, done) => {
 *   // User verification logic
 *   done(null, { id: payload.sub });
 * }));
 * ```
 *
 * @remarks
 * - The JWKS endpoint must be accessible via HTTPS
 * - Keys are cached according to the configured cache settings
 * - The function creates a jose.JWTVerifyGetKey instance internally
 * - Supports automatic key rotation when new keys appear in the JWKS
 * - Built on top of JOSE library's createRemoteJWKSet for robust key fetching
 *
 * @throws {TypeError} When jwksUri is not a valid URL
 * @throws {Error} When the JWKS endpoint is unreachable or returns invalid data
 */
export const fromRemoteJwks = (jwksUri: string, options: jose.RemoteJWKSetOptions): SecretOrKeyProvider => {
  const jwksClient: jose.JWTVerifyGetKey = jose.createRemoteJWKSet(new URL(jwksUri), options);

  return (
    _req,
    _rawJwtToken: string,
    getSecretOrKey: (err: Error | string | null, secretOrKey?: jose.JWTVerifyGetKey) => void,
  ): void => {
    getSecretOrKey(null, jwksClient);
  };
};
