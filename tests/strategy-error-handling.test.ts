import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as jose from 'jose';
import { Strategy } from '../src/strategy';
import { ExtractJwt } from '../src/extractor';
import { testStrategy } from './setup';
import type { JoseKey, VerifyCallback, VerifyCallbackWithRequest, SecretOrKeyProvider } from '../src/types';

describe('Strategy error handling', () => {
  const secretKey: JoseKey = new TextEncoder().encode('test-secret-key-that-is-long-enough');
  let mockRequest: any;
  let validJwt: string;

  beforeEach(async () => {
    mockRequest = {
      method: 'GET',
      url: '/',
      headers: {},
      body: {},
    };

    // Create a valid JWT for testing
    validJwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(secretKey);
  });

  describe('verify callback synchronous exception handling', () => {
    it('should handle synchronous errors thrown from verify callback without passReqToCallback', async () => {
      const testError = new Error('Verify callback sync error');
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        // Synchronous error thrown instead of calling done with error
        throw testError;
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.error).toBeDefined();
      expect(result.error!.error).toBe(testError);
      expect(verifyCallback).toHaveBeenCalledOnce();
    });

    it('should handle synchronous errors thrown from verify callback with passReqToCallback', async () => {
      const testError = new Error('Verify callback sync error with request');
      const verifyCallback: VerifyCallbackWithRequest = vi.fn((req, payload, done) => {
        expect(req).toBe(mockRequest);
        // Synchronous error thrown instead of calling done with error
        throw testError;
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          passReqToCallback: true,
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.error).toBeDefined();
      expect(result.error!.error).toBe(testError);
      expect(verifyCallback).toHaveBeenCalledOnce();
    });
  });

  describe('withKeyProvider Error object handling', () => {
    it('should handle Error objects (not strings) from withKeyProvider', async () => {
      const testError = new Error('Secret provider returned Error object');
      const withKeyProvider: SecretOrKeyProvider = vi.fn((req, token, done) => {
        // Pass Error object instead of string
        done(testError);
      });

      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.fail).toBeDefined();
      expect(result.fail!.challenge).toBe(testError.message);
      expect(result.fail!.status).toBe(400);
      expect(verifyCallback).not.toHaveBeenCalled();
      expect(withKeyProvider).toHaveBeenCalledOnce();
    });

    it('should handle string errors from withKeyProvider', async () => {
      const errorMessage = 'Secret provider string error';
      const withKeyProvider: SecretOrKeyProvider = vi.fn((req, token, done) => {
        done(errorMessage);
      });

      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.fail).toBeDefined();
      expect(result.fail!.challenge).toBe(errorMessage);
      expect(result.fail!.status).toBe(400);
      expect(verifyCallback).not.toHaveBeenCalled();
    });
  });

  describe('verify callback failure scenarios', () => {
    it('should handle verify callback calling done(null, false)', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        // User not found or authentication failed
        done(null, false);
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.fail).toBeDefined();
      expect(result.fail!.status).toBe(400);
      expect(verifyCallback).toHaveBeenCalledOnce();
    });

    it('should handle verify callback calling done(null, false, info)', async () => {
      const info = 'User account suspended';
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(null, false, info);
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.fail).toBeDefined();
      expect(result.fail!.challenge).toBe(info);
      expect(result.fail!.status).toBe(400);
      expect(verifyCallback).toHaveBeenCalledOnce();
    });

    it('should handle verify callback calling done(error)', async () => {
      const testError = new Error('Database connection failed');
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(testError);
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.error).toBeDefined();
      expect(result.error!.error).toBe(testError);
      expect(verifyCallback).toHaveBeenCalledOnce();
    });
  });

  describe('challenge method with error codes', () => {
    it('should include error code in challenge string', async () => {
      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      // Test the private _challenge method indirectly by triggering a failure
      // Mock the JwtVerifier to simulate a specific error that would use error codes
      const originalJwtVerifier = Strategy.JwtVerifier;
      Strategy.JwtVerifier = vi.fn((token, secretOrKey, options, callback) => {
        // Simulate an error that might come with a code
        const error = new Error('Token expired');
        callback(error);
      });

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.fail).toBeDefined();
      expect(result.fail!.challenge).toBe('Bearer realm="Users", error_description="Token expired"');
      expect(result.fail!.status).toBe(400);

      // Restore original verifier
      Strategy.JwtVerifier = originalJwtVerifier;
    });

    it('should handle challenge with both error code and description', async () => {
      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
        },
        verifyCallback,
      );

      // Access private method through type assertion to test error code path
      const challengeMethod = (strategy as any)._challenge;

      const challengeWithCode = challengeMethod('Token expired', 401);
      expect(challengeWithCode).toBe('Bearer realm="Users", error="401", error_description="Token expired"');

      const challengeWithoutCode = challengeMethod('Token expired');
      expect(challengeWithoutCode).toBe('Bearer realm="Users", error_description="Token expired"');

      const challengeEmpty = challengeMethod();
      expect(challengeEmpty).toBe('Bearer realm="Users"');
    });
  });

  describe('JWT verification edge cases', () => {
    it('should handle JwtVerifier returning no payload (edge case)', async () => {
      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      // Mock the JwtVerifier to return no payload (edge case scenario)
      const originalJwtVerifier = Strategy.JwtVerifier;
      Strategy.JwtVerifier = vi.fn((token, secretOrKey, options, callback) => {
        // Simulate successful verification but with no payload (edge case)
        callback(null, undefined);
      });

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.fail).toBeDefined();
      expect(result.fail!.challenge).toBe('Bearer realm="Users", error_description="Invalid token payload"');
      expect(result.fail!.status).toBe(400);
      expect(verifyCallback).not.toHaveBeenCalled();

      // Restore original verifier
      Strategy.JwtVerifier = originalJwtVerifier;
    });
  });

  describe('PassReqToCallback comprehensive testing', () => {
    it('should pass request as first argument when passReqToCallback is true', async () => {
      const verifyCallback: VerifyCallbackWithRequest = vi.fn((req, payload, done) => {
        expect(req).toBe(mockRequest);
        expect(req.method).toBe('GET');
        expect(req.url).toBe('/');
        expect(payload.sub).toBe('1234567890');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          passReqToCallback: true,
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.success).toBeDefined();
      expect(result.success!.user).toEqual({ id: '1234567890' });
      expect(verifyCallback).toHaveBeenCalledOnce();
      expect(verifyCallback).toHaveBeenCalledWith(mockRequest, expect.any(Object), expect.any(Function));
    });

    it('should not pass request when passReqToCallback is false', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        expect(payload.sub).toBe('1234567890');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          passReqToCallback: false,
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.success).toBeDefined();
      expect(result.success!.user).toEqual({ id: '1234567890' });
      expect(verifyCallback).toHaveBeenCalledOnce();
      expect(verifyCallback).toHaveBeenCalledWith(expect.any(Object), expect.any(Function));
    });

    it('should not pass request when passReqToCallback is undefined', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        expect(payload.sub).toBe('1234567890');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          // passReqToCallback is undefined
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.success).toBeDefined();
      expect(result.success!.user).toEqual({ id: '1234567890' });
      expect(verifyCallback).toHaveBeenCalledOnce();
      expect(verifyCallback).toHaveBeenCalledWith(expect.any(Object), expect.any(Function));
    });

    it('should handle withKeyProvider with passReqToCallback', async () => {
      const withKeyProvider: SecretOrKeyProvider = vi.fn((req, token, done) => {
        expect(req).toBe(mockRequest);
        expect(typeof token).toBe('string');
        done(null, secretKey);
      });

      const verifyCallback: VerifyCallbackWithRequest = vi.fn((req, payload, done) => {
        expect(req).toBe(mockRequest);
        expect(payload.sub).toBe('1234567890');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider,
          algorithms: ['HS256'],
          passReqToCallback: true,
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = `Bearer ${validJwt}`;

      const result = await testStrategy(strategy, mockRequest);

      expect(result.success).toBeDefined();
      expect(result.success!.user).toEqual({ id: '1234567890' });
      expect(withKeyProvider).toHaveBeenCalledOnce();
      expect(verifyCallback).toHaveBeenCalledOnce();
    });
  });
});
