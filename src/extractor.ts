import * as parser from './parser';

import type { JwtFromRequestFunction } from './types';

/**
 * Collection of JWT extraction methods for various request patterns.
 *
 * These extractors are designed to work with the Bearer token authentication scheme
 * and provide flexibility in how JWTs are transmitted in HTTP requests.
 */
export const ExtractJwt = {
  /**
   * Creates an extractor that looks for the JWT in a specific HTTP header.
   *
   * @param headerName - The name of the HTTP header to extract the JWT from
   * @returns A function that extracts JWT from the specified header
   *
   * @example
   * ```typescript
   * const extractor = ExtractJwt.fromHeader('x-access-token');
   * // Will extract JWT from: X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * ```
   */
  fromHeader(headerName: string): JwtFromRequestFunction {
    return (request: any): string | null => {
      if (request.headers && request.headers[headerName]) {
        return request.headers[headerName];
      }

      return null;
    };
  },

  /**
   * Creates an extractor that looks for the JWT in a specific body field.
   *
   * @param fieldName - The name of the body field containing the JWT
   * @returns A function that extracts JWT from the request body
   *
   * @example
   * ```typescript
   * const extractor = ExtractJwt.fromBodyField('access_token');
   * // Will extract JWT from: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
   * ```
   *
   * @remarks
   * Requires body parsing middleware (like express.json()) to be configured
   * before this extractor can access the parsed body.
   */
  fromBodyField(fieldName: string): JwtFromRequestFunction {
    return (request: any): string | null => {
      if (request.body && Object.hasOwn(request.body, fieldName)) {
        return request.body[fieldName];
      }

      return null;
    };
  },

  /**
   * Creates an extractor that looks for the JWT in the Authorization header with Bearer scheme.
   *
   * This is the most common and recommended method for JWT authentication in APIs.
   * It looks for the standard Authorization header with the Bearer scheme.
   *
   * @returns A function that extracts JWT from Authorization: Bearer <token>
   *
   * @example
   * ```typescript
   * const extractor = ExtractJwt.fromAuthHeaderAsBearerToken();
   * // Will extract JWT from: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * ```
   *
   * @remarks
   * - Only accepts the "Bearer" scheme (case-insensitive)
   * - Validates the Authorization header format strictly
   * - Returns null if the header is malformed or uses a different scheme
   */
  fromAuthHeaderAsBearerToken(): JwtFromRequestFunction {
    return (request: any): string | null => {
      if (request.headers && request.headers.authorization) {
        const authHeader = parser.parse(request.headers.authorization);

        if (authHeader) {
          return authHeader.value;
        }
      }

      return null;
    };
  },

  /**
   * Creates a composite extractor that tries multiple extraction methods in sequence.
   *
   * This allows fallback behavior where multiple extraction methods are attempted
   * until one successfully returns a token. Useful for APIs that accept JWTs
   * from multiple sources.
   *
   * @template T - The request type
   * @param extractors - Array of extractor functions to try in order
   * @returns A function that tries each extractor until one succeeds
   *
   * @throws {TypeError} When extractors parameter is not an array
   *
   * @example
   * ```typescript
   * const extractor = ExtractJwt.fromExtractors([
   *   ExtractJwt.fromAuthHeaderAsBearerToken(),
   *   ExtractJwt.fromBodyField('token'),
   *   ExtractJwt.fromHeader('x-access-token')
   * ]);
   * // Will try Authorization header first, then body field, then custom header
   * ```
   *
   * @remarks
   * - Extractors are tried in the order provided
   * - Returns the first non-null token found
   * - Returns null if all extractors fail to find a token
   */
  fromExtractors<T = any>(extractors: Array<JwtFromRequestFunction<T>>): JwtFromRequestFunction<T> {
    if (!Array.isArray(extractors)) {
      throw new TypeError('extractors.fromExtractors expects an array');
    }

    return (request: T): string | null => {
      for (const extractor of extractors) {
        const token = extractor(request);
        if (token) return token;
      }
      return null;
    };
  },
};

export default ExtractJwt;
