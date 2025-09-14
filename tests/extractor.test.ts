import { describe, it, expect } from 'vitest';
import { ExtractJwt } from '../src/extractor';

interface MockRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Record<string, any>;
}

function createMockRequest(): MockRequest {
  return {
    method: 'GET',
    url: '/',
    headers: {},
  };
}

describe('Token extractor', () => {
  describe('fromHeader', () => {
    const extractor = ExtractJwt.fromHeader('test_header');

    it('should return null when token is not present', () => {
      const req = createMockRequest();
      const token = extractor(req);
      expect(token).toBeNull();
    });

    it('should return the value from the specified header', () => {
      const req = createMockRequest();
      req.headers['test_header'] = 'abcd123';

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should return null when headers object is missing', () => {
      const req = { ...createMockRequest() };
      delete (req as any).headers;

      const token = extractor(req);
      expect(token).toBeNull();
    });
  });

  describe('fromBodyField', () => {
    const extractor = ExtractJwt.fromBodyField('test_field');

    it('should return null when no body is present', () => {
      const req = createMockRequest();
      const token = extractor(req);
      expect(token).toBeNull();
    });

    it('should return null when the specified body field is not present', () => {
      const req = createMockRequest();
      req.body = {};

      const token = extractor(req);
      expect(token).toBeNull();
    });

    it('should return the value from the specified body field', () => {
      const req = createMockRequest();
      req.body = {
        test_field: 'abcd123'
      };

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should work properly with querystring-parsed body', () => {
      const req = createMockRequest();
      req.body = { test_field: 'abcd123' };

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should handle falsy values correctly', () => {
      const req = createMockRequest();
      req.body = {
        test_field: ''
      };

      const token = extractor(req);
      expect(token).toBe('');
    });
  });

  describe('fromAuthHeaderAsBearerToken', () => {
    const extractor = ExtractJwt.fromAuthHeaderAsBearerToken();

    it('should return the value from the authorization header with Bearer scheme', () => {
      const req = createMockRequest();
      req.headers['authorization'] = 'Bearer abcd123';

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should handle lowercase bearer scheme', () => {
      const req = createMockRequest();
      req.headers['authorization'] = 'bearer abcd123';

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should return null for non-Bearer schemes', () => {
      const req = createMockRequest();
      req.headers['authorization'] = 'Basic abcd123';

      const token = extractor(req);
      expect(token).toBeNull();
    });

    it('should return null when authorization header is missing', () => {
      const req = createMockRequest();
      const token = extractor(req);
      expect(token).toBeNull();
    });

    it('should return null for malformed authorization header', () => {
      const req = createMockRequest();
      req.headers['authorization'] = 'Bearer';

      const token = extractor(req);
      expect(token).toBeNull();
    });
  });

  describe('fromExtractors', () => {
    it('should raise a type error when constructed with a non-array argument', () => {
      expect(() => {
        ExtractJwt.fromExtractors({} as any);
      }).toThrow(TypeError);
    });

    it('should return null when no extractor extracts token', () => {
      const extractor = ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromHeader('authorization')
      ]);

      const req = createMockRequest();
      const token = extractor(req);
      expect(token).toBeNull();
    });

    it('should return token found by last extractor', () => {
      const extractor = ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromHeader('authorization')
      ]);

      const req = createMockRequest();
      req.headers['authorization'] = 'abcd123';

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should return token found by first extractor', () => {
      const extractor = ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromHeader('authorization')
      ]);

      const req = createMockRequest();
      req.headers['authorization'] = 'Bearer abcd123';

      const token = extractor(req);
      expect(token).toBe('abcd123');
    });

    it('should try extractors in order until one succeeds', () => {
      const extractor = ExtractJwt.fromExtractors([
        ExtractJwt.fromHeader('x-auth-token'),
        ExtractJwt.fromBodyField('token'),
        ExtractJwt.fromAuthHeaderAsBearerToken()
      ]);

      const req = createMockRequest();
      req.body = { token: 'body-token' };
      req.headers['authorization'] = 'Bearer header-token';

      const token = extractor(req);
      expect(token).toBe('body-token'); // Should find body token first
    });

    it('should work with empty extractor array', () => {
      const extractor = ExtractJwt.fromExtractors([]);
      const req = createMockRequest();

      const token = extractor(req);
      expect(token).toBeNull();
    });
  });
});