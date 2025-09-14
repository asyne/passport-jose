import { describe, it, expect } from 'vitest';
import * as passportJose from '../src/index';
import { Strategy } from '../src/strategy';
import { ExtractJwt } from '../src/extractor';

describe('Index barrel exports', () => {
  it('should export Strategy class', () => {
    expect(passportJose.Strategy).toBeDefined();
    expect(passportJose.Strategy).toBe(Strategy);
    expect(typeof passportJose.Strategy).toBe('function');
  });

  it('should export ExtractJwt utility', () => {
    expect(passportJose.ExtractJwt).toBeDefined();
    expect(passportJose.ExtractJwt).toBe(ExtractJwt);
    expect(typeof passportJose.ExtractJwt).toBe('object');
  });

  it('should have ExtractJwt methods available', () => {
    expect(typeof passportJose.ExtractJwt.fromAuthHeaderAsBearerToken).toBe('function');
    expect(typeof passportJose.ExtractJwt.fromHeader).toBe('function');
    expect(typeof passportJose.ExtractJwt.fromBodyField).toBe('function');
    expect(typeof passportJose.ExtractJwt.fromExtractors).toBe('function');
  });

  it('should allow creating Strategy instance from exported class', () => {
    const secretKey = new TextEncoder().encode('test-secret-key-that-is-long-enough');

    const strategy = new passportJose.Strategy(
      {
        jwtFromRequest: passportJose.ExtractJwt.fromAuthHeaderAsBearerToken(),
        withSecretOrKey: secretKey,
      },
      (payload, done) => {
        done(null, { id: payload.sub });
      },
    );

    expect(strategy).toBeInstanceOf(passportJose.Strategy);
    expect(strategy.name).toBe('jwt');
  });

  it('should verify all exported types are accessible for TypeScript compilation', () => {
    // This test ensures TypeScript types are properly exported and accessible
    // by attempting to use them in type annotations

    const secretKey = new TextEncoder().encode('test-secret-key-that-is-long-enough');

    // Test StrategyOptions type
    const options: passportJose.StrategyOptions = {
      jwtFromRequest: passportJose.ExtractJwt.fromAuthHeaderAsBearerToken(),
      withSecretOrKey: secretKey,
      algorithms: ['HS256'],
    };
    expect(options).toBeDefined();

    // Test VerifyCallback type
    const verifyCallback: passportJose.VerifyCallback = (payload, done) => {
      done(null, { id: payload.sub });
    };
    expect(typeof verifyCallback).toBe('function');

    // Test JwtFromRequestFunction type
    const jwtExtractor: passportJose.JwtFromRequestFunction = passportJose.ExtractJwt.fromAuthHeaderAsBearerToken();
    expect(typeof jwtExtractor).toBe('function');

    // Test VerifiedCallback type usage
    const verifiedCallback: passportJose.VerifiedCallback = (error, user, info) => {
      // This is just for type checking
    };
    expect(typeof verifiedCallback).toBe('function');
  });
});
