import { Strategy as PassportStrategy } from 'passport-strategy';
import * as jose from 'jose';

import type {
  JoseKey,
  JwtFromRequestFunction,
  SecretOrKeyProvider as JwksFromProvider,
  StrategyOptions,
  StrategyOptionsWithRequest,
  StrategyOptionsWithoutRequest,
  VerifyCallback,
  VerifyCallbackWithRequest,
} from './types';

// Internal helper interfaces for type checking
interface WithSecret {
  withSecretOrKey: JoseKey;
}

interface WithJwksProvider {
  withKeyProvider: JwksFromProvider;
}

/**
 * Passport JWT Strategy using the modern JOSE library for secure JWT verification.
 *
 * This strategy authenticates requests containing JWTs in the Authorization header
 * using the Bearer scheme. It uses the JOSE library for robust JWT verification
 * and supports both symmetric and asymmetric key algorithms.
 *
 * @param options - Configuration options for JWT authentication
 * @param options.withSecretOrKey - JOSE-compatible key for JWT verification (CryptoKey, KeyObject, JWK, or Uint8Array).
 *                                   Required unless withKeyProvider is provided.
 * @param options.withKeyProvider - Dynamic key resolution callback in the format:
 *                                       `(request, rawJwtToken, done) => void`
 *                                       where done has signature `(err: Error | string | null, key?: JoseKey) => void`.
 *                                       REQUIRED unless withSecretOrKey is provided.
 * @param options.jwtFromRequest - (REQUIRED) Function that extracts the JWT from the request.
 *                                  Signature: `(req) => string | null`
 * @param options.issuer - Expected JWT "iss" (Issuer) claim value(s). Makes the claim presence required.
 * @param options.audience - Expected JWT "aud" (Audience) claim value(s). Makes the claim presence required.
 * @param options.algorithms - List of accepted JWS "alg" (Algorithm) values (e.g., ["HS256", "RS256"]).
 * @param options.subject - Expected JWT "sub" (Subject) claim value. Makes the claim presence required.
 * @param options.maxTokenAge - Maximum time elapsed from JWT "iat" claim (e.g., "1h", 3600).
 * @param options.clockTolerance - Clock skew tolerance for time-based claims (e.g., "30s", 30).
 * @param options.typ - Expected JWT "typ" (Type) header parameter value.
 * @param options.passReqToCallback - If true, request is passed to verify callback as first argument.
 * @param verify - User verification callback with signature:
 *                 `(payload: JWTPayload, done: VerifiedCallback) => void` if passReqToCallback is false,
 *                 `(req, payload: JWTPayload, done: VerifiedCallback) => void` if true.
 */
export class Strategy extends PassportStrategy {
  public readonly name = 'jwt';

  private readonly _getKeyOrSecret: JwksFromProvider;
  private readonly _verify: VerifyCallback | VerifyCallbackWithRequest;
  private readonly _jwtFromRequest: JwtFromRequestFunction;
  private readonly _passReqToCallback: boolean;
  private readonly _verifyOpts: jose.JWTVerifyOptions;

  constructor(options: StrategyOptionsWithoutRequest, verify: VerifyCallback);
  constructor(options: StrategyOptionsWithRequest, verify: VerifyCallbackWithRequest);
  constructor(options: StrategyOptions, verify: VerifyCallback | VerifyCallbackWithRequest) {
    super();

    const _sumOptions = options as Partial<WithSecret & WithJwksProvider>;
    if (_sumOptions.withSecretOrKey && _sumOptions.withKeyProvider) {
      throw new TypeError('JwtStrategy has been given both a withSecretOrKey and a withKeyProvider');
    } else if (!_sumOptions.withSecretOrKey && !_sumOptions.withKeyProvider) {
      throw new TypeError('JwtStrategy requires either a withSecretOrKey or a withKeyProvider');
    }

    if ((options as WithJwksProvider).withKeyProvider) {
      this._getKeyOrSecret = (options as WithJwksProvider).withKeyProvider;
    } else {
      this._getKeyOrSecret = (_request, _jwt, done) => done(null, (options as WithSecret).withSecretOrKey);
    }

    this._verify = verify;
    if (!this._verify) {
      throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
      throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }

    this._passReqToCallback = Boolean(options.passReqToCallback);

    // Build jose verification options
    this._verifyOpts = {
      audience: options.audience,
      issuer: options.issuer,
      algorithms: options.algorithms,
      clockTolerance: options.clockTolerance,
      subject: options.subject,
      maxTokenAge: options.maxTokenAge,
      typ: options.typ,
      requiredClaims: options.requiredClaims,
      crit: options.crit,
    };
  }

  /**
   * Allow for injection of JWT Verifier.
   *
   * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
   * process from failures in the passport related mechanics of authentication.
   *
   * Note that this should only be replaced in tests.
   */
  static JwtVerifier<T extends JoseKey | jose.JWTVerifyGetKey>(
    token: string | Uint8Array,
    secretOrKeyOrGetKey: T,
    options: jose.JWTVerifyOptions,
    callback: (err: Error | null, payload?: jose.JWTPayload) => void,
  ): void {
    jose
      .jwtVerify(token, secretOrKeyOrGetKey as any, options)
      .then(({ payload }) => callback(null, payload))
      .catch(callback);
  }

  /**
   * Authenticates an HTTP request using JWT Bearer token authentication.
   *
   * This method implements the core authentication logic:
   * 1. Extracts JWT token from request using configured extractor
   * 2. Resolves the verification key (static or dynamic)
   * 3. Verifies JWT using JOSE library with configured options
   * 4. Calls user-provided verification callback with decoded payload
   * 5. Handles authentication success/failure according to Passport conventions
   *
   * @param req - The HTTP request object to authenticate
   *
   * @remarks
   * - Follows Passport strategy conventions for success/failure handling
   * - Uses JOSE library for robust JWT verification
   * - Supports both synchronous and asynchronous key resolution
   * - Provides detailed error information through challenge strings
   * - Handles Bearer token scheme validation strictly
   */
  authenticate(req: any) {
    const token = this._jwtFromRequest(req);

    if (!token) {
      return this.fail(this._challenge('No auth token'), 400);
    }

    this._getKeyOrSecret(
      req,
      token,
      (secretOrKeyError: Error | string | null, secretOrKey?: JoseKey | jose.JWTVerifyGetKey) => {
        if (secretOrKeyError) {
          return this.fail(typeof secretOrKeyError === 'string' ? secretOrKeyError : secretOrKeyError.message, 400);
        }

        // Verify the JWT - use type assertion to work around overload resolution with union types
        Strategy.JwtVerifier(token, secretOrKey!, this._verifyOpts, (err: Error | null, payload?: jose.JWTPayload) => {
          if (err) {
            return this.fail(this._challenge(err.message), 400);
          }

          if (!payload) {
            return this.fail(this._challenge('Invalid token payload'), 400);
          }

          // Pass the parsed token to the user
          const verified = (err: Error | null, user?: unknown | false, info?: unknown) => {
            if (err) {
              return this.error(err);
            } else if (!user) {
              return this.fail(info as string, 400);
            } else {
              return this.success(user, info);
            }
          };

          try {
            if (this._passReqToCallback) {
              (this._verify as VerifyCallbackWithRequest)(req, payload, verified);
            } else {
              (this._verify as VerifyCallback)(payload, verified);
            }
          } catch (err) {
            this.error(err as Error);
          }
        });
      },
    );
  }

  private _challenge(description?: string, code?: number) {
    let challenge = 'Bearer realm="Users"';

    if (code) {
      challenge += `, error="${code}"`;
    }
    if (description) {
      challenge += `, error_description="${description}"`;
    }

    return challenge;
  }
}
