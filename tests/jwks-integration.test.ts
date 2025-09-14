import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as jose from 'jose';
import { Strategy } from '../src/strategy';
import { ExtractJwt } from '../src/extractor';
import { fromRemoteJwks } from '../src/jwks/provider';
import { testStrategy } from './setup';

// Mock the jose module
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(),
  jwtVerify: vi.fn(),
}));

describe('JWKS Provider Integration', () => {
  const mockCreateRemoteJWKSet = vi.mocked(jose.createRemoteJWKSet);
  const mockJwtVerify = vi.mocked(jose.jwtVerify);

  // Create a proper mock RemoteJWKSet
  const mockJwksClient = vi.fn().mockResolvedValue(new Uint8Array()) as any;
  mockJwksClient.coolingDown = false;
  mockJwksClient.fresh = true;
  mockJwksClient.reloading = false;
  mockJwksClient.reload = vi.fn().mockResolvedValue(undefined);
  mockJwksClient.jwks = vi.fn().mockReturnValue(undefined);

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateRemoteJWKSet.mockReturnValue(mockJwksClient);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Strategy with fromRemoteJwks', () => {
    const jwksUri = 'https://example.com/.well-known/jwks.json';
    const jwksOptions = { cacheMaxAge: 30000 };

    it('should create a strategy using fromRemoteJwks as withKeyProvider', () => {
      const verifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(jwksUri, jwksOptions),
          algorithms: ['RS256'],
        },
        verifyCallback,
      );

      expect(strategy).toBeInstanceOf(Strategy);
      expect(strategy.name).toBe('jwt');
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledOnce();
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(jwksUri), jwksOptions);
    });

    it('should authenticate successfully with valid JWT and JWKS', async () => {
      const mockPayload = {
        sub: 'user123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: 'https://example.com',
      };

      const mockProtectedHeader = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'key-id-123',
      };

      mockJwtVerify.mockResolvedValue({
        payload: mockPayload,
        protectedHeader: mockProtectedHeader,
        key: new Uint8Array(),
      });

      const verifyCallback = vi.fn((payload, done) => {
        done(null, { id: payload.sub, email: 'user@example.com' });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(jwksUri, jwksOptions),
          algorithms: ['RS256'],
          issuer: 'https://example.com',
        },
        verifyCallback,
      );

      const mockRequest = {
        headers: {
          authorization: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      };

      const result = await testStrategy(strategy, mockRequest);

      expect(result).toAuthenticate();
      expect(mockJwtVerify).toHaveBeenCalledOnce();
      expect(verifyCallback).toHaveBeenCalledWith(mockPayload, expect.any(Function));

      // Verify that the JWKS client was used for verification
      const [jwt, getKey, options] = mockJwtVerify.mock.calls[0];
      expect(jwt).toBe('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
      expect(getKey).toBe(mockJwksClient);
      expect(options).toMatchObject({
        algorithms: ['RS256'],
        issuer: 'https://example.com',
      });
    });

    it('should fail authentication when JWT verification fails', async () => {
      mockJwtVerify.mockRejectedValue(new Error('JWT expired'));

      const verifyCallback = vi.fn();

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(jwksUri, jwksOptions),
          algorithms: ['RS256'],
        },
        verifyCallback,
      );

      const mockRequest = {
        headers: {
          authorization: 'Bearer expired.jwt.token',
        },
      };

      const result = await testStrategy(strategy, mockRequest);

      expect(result).toFail();
      expect(mockJwtVerify).toHaveBeenCalledOnce();
      expect(verifyCallback).not.toHaveBeenCalled();
    });

    it('should work with passReqToCallback option', async () => {
      const mockPayload = {
        sub: 'user456',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      mockJwtVerify.mockResolvedValue({
        payload: mockPayload,
        protectedHeader: { alg: 'RS256', typ: 'JWT' },
        key: new Uint8Array(),
      });

      const verifyCallback = vi.fn((req, payload, done) => {
        // Verify request is passed correctly
        expect(req).toMatchObject({
          headers: { authorization: expect.stringContaining('Bearer') },
          method: 'GET',
        });
        done(null, { id: payload.sub, requestMethod: req.method });
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(jwksUri, jwksOptions),
          algorithms: ['RS256'],
          passReqToCallback: true,
        },
        verifyCallback,
      );

      const mockRequest = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid.jwt.token',
        },
      };

      const result = await testStrategy(strategy, mockRequest);

      expect(result).toAuthenticate();
      expect(verifyCallback).toHaveBeenCalledWith(mockRequest, mockPayload, expect.any(Function));
    });

    it('should support multiple JWKS providers for different issuers', () => {
      const auth0Uri = 'https://dev-123.auth0.com/.well-known/jwks.json';
      const azureUri = 'https://login.microsoftonline.com/tenant/discovery/v2.0/keys';

      const auth0Strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(auth0Uri, { cacheMaxAge: 600000 }),
          algorithms: ['RS256'],
          issuer: 'https://dev-123.auth0.com/',
        },
        vi.fn((payload, done) => done(null, { id: payload.sub, provider: 'auth0' })),
      );

      const azureStrategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(azureUri, { cacheMaxAge: 300000 }),
          algorithms: ['RS256'],
          issuer: 'https://login.microsoftonline.com/tenant/v2.0',
        },
        vi.fn((payload, done) => done(null, { id: payload.sub, provider: 'azure' })),
      );

      expect(auth0Strategy).toBeInstanceOf(Strategy);
      expect(azureStrategy).toBeInstanceOf(Strategy);

      // Should have created two separate JWKS clients
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledTimes(2);
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(auth0Uri), { cacheMaxAge: 600000 });
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(azureUri), { cacheMaxAge: 300000 });
    });

    it('should handle JWKS client errors gracefully', async () => {
      // Mock the JWKS provider to call the callback with an error
      const errorProvider = vi.fn((req, token, done) => {
        done(new Error('JWKS endpoint unreachable'));
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: errorProvider,
          algorithms: ['RS256'],
        },
        vi.fn(),
      );

      const mockRequest = {
        headers: {
          authorization: 'Bearer some.jwt.token',
        },
      };

      const result = await testStrategy(strategy, mockRequest);

      expect(result).toFail('JWKS endpoint unreachable', 400);
      expect(errorProvider).toHaveBeenCalledOnce();
    });

    it('should respect algorithm constraints with JWKS', async () => {
      const mockPayload = {
        sub: 'user789',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      mockJwtVerify.mockResolvedValue({
        payload: mockPayload,
        protectedHeader: { alg: 'RS256', typ: 'JWT' },
        key: new Uint8Array(),
      });

      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks(jwksUri, jwksOptions),
          algorithms: ['RS256', 'RS512'], // Only allow RSA algorithms
          audience: 'api.example.com',
        },
        vi.fn((payload, done) => done(null, { id: payload.sub })),
      );

      const mockRequest = {
        headers: {
          authorization: 'Bearer rsa.signed.token',
        },
      };

      const result = await testStrategy(strategy, mockRequest);

      expect(result).toAuthenticate();

      // Verify that algorithm and audience constraints are passed to jose.jwtVerify
      const [, , options] = mockJwtVerify.mock.calls[0];
      expect(options).toMatchObject({
        algorithms: ['RS256', 'RS512'],
        audience: 'api.example.com',
      });
    });
  });

  describe('Real-world scenarios', () => {
    it('should work with typical Auth0 configuration', () => {
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          withKeyProvider: fromRemoteJwks('https://dev-example.auth0.com/.well-known/jwks.json', {
            cacheMaxAge: 600000, // 10 minutes
            cooldownDuration: 30000, // 30 seconds
          }),
          algorithms: ['RS256'],
          issuer: 'https://dev-example.auth0.com/',
          audience: 'https://api.myapp.com',
        },
        (payload, done) => {
          // Typical Auth0 payload structure
          const user = {
            id: payload.sub,
            email: payload.email,
            roles: payload['https://api.myapp.com/roles'],
          };
          done(null, user);
        },
      );

      expect(strategy).toBeInstanceOf(Strategy);
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
        new URL('https://dev-example.auth0.com/.well-known/jwks.json'),
        {
          cacheMaxAge: 600000,
          cooldownDuration: 30000,
        },
      );
    });

    it('should work with Azure AD configuration', () => {
      const tenantId = '12345678-1234-1234-1234-123456789012';
      const strategy = new Strategy(
        {
          jwtFromRequest: ExtractJwt.fromHeader('x-access-token'),
          withKeyProvider: fromRemoteJwks(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`, {
            cacheMaxAge: 300000, // 5 minutes
            timeoutDuration: 10000, // 10 seconds timeout
          }),
          algorithms: ['RS256'],
          issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
          audience: 'api://my-app-registration-id',
        },
        (payload, done) => {
          // Typical Azure AD payload structure
          const user = {
            id: payload.sub || payload.oid,
            email: payload.email || payload.preferred_username,
            tenantId: payload.tid,
            appId: payload.appid,
          };
          done(null, user);
        },
      );

      expect(strategy).toBeInstanceOf(Strategy);
    });
  });
});
