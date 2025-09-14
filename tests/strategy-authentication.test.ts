import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as jose from 'jose';
import { Strategy } from '../src/strategy';
import { ExtractJwt } from '../src/extractor';
import { testStrategy } from './setup';
import type { JoseKey, VerifyCallback, SecretOrKeyProvider } from '../src/types';

describe('Strategy authentication', () => {
  const secretKey: JoseKey = new TextEncoder().encode('test-secret-key-that-is-long-enough');
  let mockRequest: any;

  beforeEach(() => {
    mockRequest = {
      method: 'GET',
      url: '/',
      headers: {},
      body: {},
    };
  });

  describe('JWT verification process', () => {
    it('should call with the right secret as an argument', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      // Create a valid JWT
      const jwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
      expect(verifyCallback).toHaveBeenCalled();
    });

    it('should call with the right issuer option', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        expect(payload.iss).toBe('test-issuer');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          issuer: 'test-issuer',
        },
        verifyCallback,
      );

      // Create JWT with issuer
      const jwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer('test-issuer')
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
      expect(verifyCallback).toHaveBeenCalled();
    });

    it('should call with the right audience option', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        expect(payload.aud).toBe('test-audience');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          audience: 'test-audience',
        },
        verifyCallback,
      );

      // Create JWT with audience
      const jwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('test-audience')
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
      expect(verifyCallback).toHaveBeenCalled();
    });

    it('should handle maxTokenAge option', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          maxTokenAge: '1h',
        },
        verifyCallback,
      );

      // Create JWT with recent iat
      const jwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
    });

    it('should handle clockTolerance option', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          clockTolerance: 30,
        },
        verifyCallback,
      );

      const jwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
    });
  });

  describe('handling valid JWT', () => {
    it('should call verify with the correct payload', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        expect(payload.sub).toBe('1234567890');
        expect(payload.name).toBe('John Doe');
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      const jwt = await new jose.SignJWT({ sub: '1234567890', name: 'John Doe' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
      expect(verifyCallback).toHaveBeenCalledOnce();
    });
  });

  describe('handling invalid JWT', () => {
    it('should not call verify for invalid token', async () => {
      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = 'Bearer invalid-token';

      const result = await testStrategy(strategy, mockRequest);
      expect(result.fail).toBeDefined();
      expect(verifyCallback).not.toHaveBeenCalled();
    });

    it('should fail with error message for invalid token', async () => {
      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      mockRequest.headers.authorization = 'Bearer invalid-token';

      const result = await testStrategy(strategy, mockRequest);
      expect(result.fail).toBeDefined();

      const failResult = result.fail!;
      expect(failResult.status).toBe(400);
      expect(failResult.challenge).toContain('Bearer realm="Users"');
    });
  });

  describe('handling missing JWT', () => {
    it('should fail authentication when no token is present', async () => {
      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      const result = await testStrategy(strategy, mockRequest);
      expect(result.fail).toBeDefined();

      const failResult = result.fail!;
      expect(failResult.status).toBe(400);
      expect(failResult.challenge).toContain('No auth token');
    });

    it('should not try to verify anything when no token present', async () => {
      const verifyCallback: VerifyCallback = vi.fn();
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withSecretOrKey: secretKey,
        },
        verifyCallback,
      );

      const result = await testStrategy(strategy, mockRequest);
      expect(result.fail).toBeDefined();
      expect(verifyCallback).not.toHaveBeenCalled();
    });
  });

  describe('withKeyProvider functionality', () => {
    it('should call withKeyProvider with request and token', async () => {
      const withKeyProvider: SecretOrKeyProvider = vi.fn((req, token, done) => {
        expect(req).toBe(mockRequest);
        expect(typeof token).toBe('string');
        done(null, secretKey);
      });

      const verifyCallback: VerifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider,
          algorithms: ['HS256'],
        },
        verifyCallback,
      );

      const jwt = await new jose.SignJWT({ sub: '1234567890' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);

      mockRequest.headers.authorization = `Bearer ${jwt}`;

      const result = await testStrategy(strategy, mockRequest);
      expect(result.success).toBeDefined();
      expect(withKeyProvider).toHaveBeenCalledOnce();
    });

    it('should handle withKeyProvider errors', async () => {
      const withKeyProvider: SecretOrKeyProvider = vi.fn((req, token, done) => {
        done('Secret provider error');
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

      mockRequest.headers.authorization = 'Bearer some-token';

      const result = await testStrategy(strategy, mockRequest);
      expect(result.fail).toBeDefined();
      expect(verifyCallback).not.toHaveBeenCalled();
    });
  });
});
