import { describe, it, expect } from 'vitest';
import { Strategy } from '../src/strategy';
import type { JoseKey, VerifyCallback, SecretOrKeyProvider } from '../src/types';

describe('Strategy initialization', () => {
  const secretKey: JoseKey = new TextEncoder().encode('test-secret');
  const mockJwtFromRequest = () => 'mock-token';
  const mockVerifyCallback: VerifyCallback = (payload, done) => done(null, { id: payload.sub });

  it('should be named jwt', () => {
    const strategy = new Strategy(
      { jwtFromRequest: mockJwtFromRequest, withSecretOrKey: secretKey },
      mockVerifyCallback,
    );

    expect(strategy.name).toBe('jwt');
  });

  it('should throw if constructed without a verify callback', () => {
    expect(() => {
      new (Strategy as any)({
        jwtFromRequest: mockJwtFromRequest,
        withSecretOrKey: secretKey,
      });
    }).toThrow(TypeError);
  });

  it('should throw if constructed without withSecretOrKey or withKeyProvider', () => {
    expect(() => {
      new Strategy({ jwtFromRequest: mockJwtFromRequest } as any, mockVerifyCallback);
    }).toThrow(TypeError);
  });

  it('should throw if constructed with both withSecretOrKey and withKeyProvider', () => {
    const mockWithKeyProvider: SecretOrKeyProvider = (req, token, done) => {
      done(null, secretKey);
    };

    expect(() => {
      new Strategy(
        {
          withSecretOrKey: secretKey,
          withKeyProvider: mockWithKeyProvider,
          jwtFromRequest: mockJwtFromRequest,
        },
        mockVerifyCallback,
      );
    }).toThrow(TypeError);
  });

  it('should throw if constructed without a jwtFromRequest function', () => {
    expect(() => {
      new Strategy({ withSecretOrKey: secretKey } as any, mockVerifyCallback);
    }).toThrow(TypeError);
  });

  it('should accept valid configuration with withSecretOrKey', () => {
    expect(() => {
      new Strategy(
        {
          jwtFromRequest: mockJwtFromRequest,
          withSecretOrKey: secretKey,
          algorithms: ['HS256'],
          issuer: 'test-issuer',
        },
        mockVerifyCallback,
      );
    }).not.toThrow();
  });

  it('should accept valid configuration with withKeyProvider', () => {
    const mockWithKeyProvider: SecretOrKeyProvider = (req, token, done) => {
      done(null, secretKey);
    };

    expect(() => {
      new Strategy(
        {
          jwtFromRequest: mockJwtFromRequest,
          withKeyProvider: mockWithKeyProvider,
          algorithms: ['HS256'],
        },
        mockVerifyCallback,
      );
    }).not.toThrow();
  });

  it('should handle different JOSE key types', () => {
    const uint8ArrayKey = new TextEncoder().encode('test-secret');

    expect(() => {
      new Strategy({ jwtFromRequest: mockJwtFromRequest, withSecretOrKey: uint8ArrayKey }, mockVerifyCallback);
    }).not.toThrow();
  });

  it('should store configuration options correctly', () => {
    const options = {
      jwtFromRequest: mockJwtFromRequest,
      withSecretOrKey: secretKey,
      algorithms: ['HS256', 'RS256'],
      issuer: 'test-issuer',
      audience: 'test-audience',
      subject: 'test-subject',
      maxTokenAge: '1h',
      clockTolerance: 30,
      typ: 'JWT',
    };

    const strategy = new Strategy(options, mockVerifyCallback);

    // Verify that the strategy was created successfully
    expect(strategy.name).toBe('jwt');
    expect(typeof strategy.authenticate).toBe('function');
  });
});
