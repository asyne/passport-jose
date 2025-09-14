import * as jose from 'jose';

/**
 * Function interface for extracting JWT tokens from HTTP requests.
 *
 * @template T - The request type (defaults to any for flexibility)
 * @param req - The HTTP request object
 * @returns The extracted JWT token as a string, or null if not found
 */
export interface JwtFromRequestFunction<T = any> {
  (req: T): string | null;
}

/**
 * Union type representing all valid key formats accepted by the JOSE library for JWT verification.
 *
 * This type encompasses the various key formats that can be used with JOSE's jwtVerify function:
 * - `CryptoKey`: Web Crypto API key object (modern browsers and Node.js 15.0+)
 * - `KeyObject`: Node.js crypto module key object (Node.js crypto.createSecretKey, etc.)
 * - `JWK`: JSON Web Key format (RFC 7517)
 * - `Uint8Array`: Raw key material as byte array (for symmetric keys)
 *
 * @example
 * ```typescript
 * // Symmetric key as Uint8Array
 * const secretKey: JoseKey = new TextEncoder().encode('your-secret-key');
 *
 * // JWK format
 * const jwkKey: JoseKey = {
 *   kty: 'RSA',
 *   use: 'sig',
 *   n: '...',
 *   e: 'AQAB'
 * };
 *
 * // Web Crypto API key
 * const cryptoKey: JoseKey = await crypto.subtle.importKey(...);
 * ```
 *
 * @remarks
 * - Prefer modern key formats (CryptoKey, KeyObject) for better security
 * - Uint8Array is suitable for simple symmetric keys
 * - JWK format is useful for key distribution and storage
 * - All formats are validated by the JOSE library during verification
 */
export type JoseKey = jose.CryptoKey | jose.KeyObject | jose.JWK | Uint8Array;

/**
 * Callback interface for passport authentication verification.
 *
 * This callback is called by Passport to signal the outcome of the authentication process.
 *
 * @param error - Error that occurred during authentication, null if successful
 * @param user - The authenticated user object, false if authentication failed
 * @param info - Additional information about the authentication result
 */
export interface VerifiedCallback {
  (error: Error | null, user?: unknown | false, info?: unknown): void;
}

/**
 * Verification callback function for JWT payload validation.
 *
 * This function is called after successful JWT verification to validate the user
 * associated with the JWT payload.
 *
 * @param payload - The decoded JWT payload
 * @param done - Callback to signal authentication result
 */
export type VerifyCallback = (payload: jose.JWTPayload, done: VerifiedCallback) => void;

/**
 * Verification callback function that includes the request object.
 *
 * This function is called when `passReqToCallback` is true, providing access
 * to the original request object for additional validation logic.
 *
 * @template T - The request type (defaults to any for flexibility)
 * @param req - The HTTP request object
 * @param payload - The decoded JWT payload
 * @param done - Callback to signal authentication result
 */
export type VerifyCallbackWithRequest<T = any> = (req: T, payload: jose.JWTPayload, done: VerifiedCallback) => void;

/**
 * Dynamic secret or key provider function.
 *
 * This function allows for dynamic key resolution based on the request and JWT token.
 * Useful for multi-tenant applications or when keys need to be resolved at runtime.
 *
 * @template T - The request type (defaults to any for flexibility)
 * @param request - The HTTP request object
 * @param rawJwtToken - The raw JWT token string
 * @param done - Callback to provide the resolved key or error
 */
export interface SecretOrKeyProvider<T = any> {
  (
    request: T,
    rawJwtToken: string,
    getSecretOrKey: (err: Error | string | null, secretOrKey?: JoseKey | jose.JWTVerifyGetKey) => void,
  ): void;
}

/**
 * Base strategy options extending JOSE JWT verification options.
 *
 * This interface combines JOSE library options with the required JWT extractor function.
 */
interface BaseStrategyOptions extends Omit<jose.JWTVerifyOptions, 'currentDate'> {
  /** Function that extracts the JWT from the request */
  readonly jwtFromRequest: JwtFromRequestFunction;
}

/**
 * Strategy options when using a dynamic secret or key provider.
 */
interface WithKeyProvider extends BaseStrategyOptions {
  /** Dynamic key resolution callback */
  readonly withKeyProvider: SecretOrKeyProvider;
}

/**
 * Strategy options when using a static secret or key.
 */
interface WithSecretOrKey extends BaseStrategyOptions {
  /** Static key for JWT verification */
  readonly withSecretOrKey: JoseKey;
}

/**
 * Union type for strategy options with either static key or key provider.
 *
 * Ensures that exactly one of secretOrKey or secretOrKeyProvider is provided.
 */
type StrategyOptionsWithSecret = Omit<WithSecretOrKey, 'withKeyProvider'> | Omit<WithKeyProvider, 'withSecretOrKey'>;

/**
 * Strategy options when the request should be passed to the verify callback.
 *
 * When `passReqToCallback` is true, the verify callback will receive the request
 * as its first parameter.
 */
export type StrategyOptionsWithRequest = StrategyOptionsWithSecret & {
  readonly passReqToCallback: true;
};

/**
 * Strategy options when the request should not be passed to the verify callback.
 *
 * This is the default behavior where the verify callback only receives the JWT payload.
 */
export type StrategyOptionsWithoutRequest = StrategyOptionsWithSecret & {
  readonly passReqToCallback?: false;
};

/**
 * Complete strategy options type supporting both callback patterns.
 *
 * This union type ensures type safety based on the `passReqToCallback` option.
 */
export type StrategyOptions = StrategyOptionsWithRequest | StrategyOptionsWithoutRequest;
