import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as jose from 'jose';
import { fromRemoteJwks } from '../src/jwks/provider';

// Mock the jose module
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(),
}));

describe('JWKS Provider', () => {
  // Create a proper mock RemoteJWKSet
  const mockJwksClient = vi.fn().mockResolvedValue(new Uint8Array()) as any;
  mockJwksClient.coolingDown = false;
  mockJwksClient.fresh = true;
  mockJwksClient.reloading = false;
  mockJwksClient.reload = vi.fn().mockResolvedValue(undefined);
  mockJwksClient.jwks = vi.fn().mockReturnValue(undefined);

  const mockCreateRemoteJWKSet = vi.mocked(jose.createRemoteJWKSet);

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateRemoteJWKSet.mockReturnValue(mockJwksClient);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('fromRemoteJwks', () => {
    const jwksUri = 'https://example.com/.well-known/jwks.json';
    const defaultOptions = { cacheMaxAge: 30000 };

    it('should create a SecretOrKeyProvider function', () => {
      const provider = fromRemoteJwks(jwksUri, defaultOptions);

      expect(typeof provider).toBe('function');
      expect(provider.length).toBe(3); // req, rawJwtToken, getSecretOrKey
    });

    it('should call jose.createRemoteJWKSet with correct parameters', () => {
      const customOptions = {
        cacheMaxAge: 60000,
        cooldownDuration: 5000,
        timeoutDuration: 10000,
      };

      fromRemoteJwks(jwksUri, customOptions);

      expect(mockCreateRemoteJWKSet).toHaveBeenCalledOnce();
      expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(jwksUri), customOptions);
    });

    it('should create URL object from string URI', () => {
      fromRemoteJwks(jwksUri, defaultOptions);

      const [urlArg] = mockCreateRemoteJWKSet.mock.calls[0];
      expect(urlArg).toBeInstanceOf(URL);
      expect(urlArg.href).toBe(jwksUri);
    });

    it('should handle different JWKS URI formats', () => {
      const testCases = [
        'https://auth0.com/.well-known/jwks.json',
        'https://login.microsoftonline.com/common/discovery/v2.0/keys',
        'https://www.googleapis.com/oauth2/v3/certs',
      ];

      testCases.forEach((uri, index) => {
        vi.clearAllMocks();
        fromRemoteJwks(uri, defaultOptions);

        const [urlArg] = mockCreateRemoteJWKSet.mock.calls[0];
        expect(urlArg.href).toBe(uri);
      });
    });

    describe('returned SecretOrKeyProvider function', () => {
      it('should call getSecretOrKey with jwks client when invoked', () => {
        const provider = fromRemoteJwks(jwksUri, defaultOptions);
        const mockRequest = { headers: {} };
        const mockJwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...';
        const mockGetSecretOrKey = vi.fn();

        provider(mockRequest, mockJwtToken, mockGetSecretOrKey);

        expect(mockGetSecretOrKey).toHaveBeenCalledOnce();
        expect(mockGetSecretOrKey).toHaveBeenCalledWith(null, mockJwksClient);
      });

      it('should pass null as error and jwks client as secret', () => {
        const provider = fromRemoteJwks(jwksUri, defaultOptions);
        const mockGetSecretOrKey = vi.fn();

        provider({}, 'token', mockGetSecretOrKey);

        const [error, secretOrKey] = mockGetSecretOrKey.mock.calls[0];
        expect(error).toBeNull();
        expect(secretOrKey).toBe(mockJwksClient);
      });

      it('should ignore request and token parameters', () => {
        const provider = fromRemoteJwks(jwksUri, defaultOptions);
        const mockGetSecretOrKey = vi.fn();

        // Call with different request and token values
        provider({ method: 'POST', headers: { custom: 'header' } }, 'different-token', mockGetSecretOrKey);
        provider(null as any, '', mockGetSecretOrKey);
        provider({} as any, 'some-token', mockGetSecretOrKey);

        // Should always call with same parameters regardless of input
        expect(mockGetSecretOrKey).toHaveBeenCalledTimes(3);
        mockGetSecretOrKey.mock.calls.forEach((call) => {
          expect(call[0]).toBeNull();
          expect(call[1]).toBe(mockJwksClient);
        });
      });
    });

    describe('edge cases and error handling', () => {
      it('should handle invalid URI by letting URL constructor throw', () => {
        expect(() => {
          fromRemoteJwks('invalid-uri', defaultOptions);
        }).toThrow();
      });

      it('should handle empty URI by letting URL constructor throw', () => {
        expect(() => {
          fromRemoteJwks('', defaultOptions);
        }).toThrow();
      });

      it('should work with minimal options', () => {
        const provider = fromRemoteJwks(jwksUri, {});

        expect(typeof provider).toBe('function');
        expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(jwksUri), {});
      });

      it('should preserve all options passed to createRemoteJWKSet', () => {
        const complexOptions = {
          cacheMaxAge: 600000,
          cooldownDuration: 30000,
          timeoutDuration: 5000,
          agent: {} as any, // HTTP agent
          headers: { 'User-Agent': 'test-agent' },
        };

        fromRemoteJwks(jwksUri, complexOptions);

        expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(jwksUri), complexOptions);
      });
    });

    describe('integration with passport strategy', () => {
      it('should create provider compatible with passport strategy interface', () => {
        const provider = fromRemoteJwks(jwksUri, defaultOptions);

        // Simulate how passport strategy would call this
        const mockReq = { method: 'GET', url: '/protected' };
        const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...';
        let capturedError: any;
        let capturedKey: any;

        const getSecretOrKeyCallback = (err: any, key: any) => {
          capturedError = err;
          capturedKey = key;
        };

        provider(mockReq, mockToken, getSecretOrKeyCallback);

        expect(capturedError).toBeNull();
        expect(capturedKey).toBe(mockJwksClient);
        expect(typeof capturedKey).toBe('function'); // JOSE JWTVerifyGetKey
      });

      it('should work with TypeScript SecretOrKeyProvider interface', () => {
        // This test ensures the function signature matches the expected interface
        const provider = fromRemoteJwks(jwksUri, defaultOptions);

        // TypeScript compilation test - these should not cause type errors
        const testProvider: typeof provider = provider;
        expect(testProvider).toBe(provider);

        // Test the callback signature
        const testCallback = (err: Error | string | null, secretOrKey?: any) => {
          expect(err).toBeNull();
          expect(secretOrKey).toBeDefined();
        };

        provider({}, 'token', testCallback);
      });
    });

    describe('caching behavior through jose library', () => {
      it('should create only one JWK set client per provider instance', () => {
        const provider = fromRemoteJwks(jwksUri, defaultOptions);

        // Call the provider multiple times
        const mockGetSecretOrKey = vi.fn();
        provider({}, 'token1', mockGetSecretOrKey);
        provider({}, 'token2', mockGetSecretOrKey);
        provider({}, 'token3', mockGetSecretOrKey);

        // Should only create one remote JWK set
        expect(mockCreateRemoteJWKSet).toHaveBeenCalledOnce();

        // But should return the same client each time
        expect(mockGetSecretOrKey).toHaveBeenCalledTimes(3);
        mockGetSecretOrKey.mock.calls.forEach((call) => {
          expect(call[1]).toBe(mockJwksClient);
        });
      });

      it('should create separate clients for different providers', () => {
        const provider1 = fromRemoteJwks('https://auth1.com/jwks', defaultOptions);
        const provider2 = fromRemoteJwks('https://auth2.com/jwks', defaultOptions);

        expect(mockCreateRemoteJWKSet).toHaveBeenCalledTimes(2);

        const calls = mockCreateRemoteJWKSet.mock.calls;
        expect(calls[0][0].href).toBe('https://auth1.com/jwks');
        expect(calls[1][0].href).toBe('https://auth2.com/jwks');
      });
    });

    describe('common JWKS provider scenarios', () => {
      it('should work with Auth0 JWKS endpoint', () => {
        const auth0Uri = 'https://dev-123.auth0.com/.well-known/jwks.json';
        const provider = fromRemoteJwks(auth0Uri, { cacheMaxAge: 600000 });

        expect(typeof provider).toBe('function');
        expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(auth0Uri), { cacheMaxAge: 600000 });
      });

      it('should work with Microsoft Azure AD JWKS endpoint', () => {
        const azureUri = 'https://login.microsoftonline.com/common/discovery/v2.0/keys';
        const provider = fromRemoteJwks(azureUri, {
          cacheMaxAge: 300000,
          cooldownDuration: 30000,
        });

        expect(typeof provider).toBe('function');
        expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(azureUri), {
          cacheMaxAge: 300000,
          cooldownDuration: 30000,
        });
      });

      it('should work with Google JWKS endpoint', () => {
        const googleUri = 'https://www.googleapis.com/oauth2/v3/certs';
        const provider = fromRemoteJwks(googleUri, {
          cacheMaxAge: 86400000, // 24 hours
          timeoutDuration: 10000,
        });

        expect(typeof provider).toBe('function');
        expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(new URL(googleUri), {
          cacheMaxAge: 86400000,
          timeoutDuration: 10000,
        });
      });
    });
  });
});
