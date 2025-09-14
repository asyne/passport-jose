/**
 * Regular expression to validate Bearer authentication scheme (case-insensitive).
 * Compiled once for efficiency.
 */
const BEARER_SCHEME_REGEX = /^Bearer$/i;

/**
 * Represents a parsed Authorization header with scheme and credentials.
 *
 * @interface AuthHeader
 * @property scheme - The authentication scheme (e.g., "Bearer")
 * @property value - The credentials/token value
 */
export interface AuthHeader {
  scheme: string;
  value: string;
}

/**
 * Parses an Authorization header value to extract the authentication scheme and token.
 *
 * This function specifically validates the Bearer authentication scheme format
 * according to RFC 6750. It expects the header to be in the format:
 * "Bearer <token-value>"
 *
 * @param headerValue - The raw Authorization header value
 * @returns Parsed header object with scheme and value, or null if invalid
 *
 * @example
 * ```typescript
 * const result = parseAuthHeader('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
 * // Returns: { scheme: 'Bearer', value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' }
 *
 * const invalid = parseAuthHeader('Basic dXNlcjpwYXNz');
 * // Returns: null (not Bearer scheme)
 * ```
 *
 * @remarks
 * - Only accepts "Bearer" scheme (case-insensitive per RFC 6750)
 * - Requires exactly one space between scheme and token
 * - Returns null for malformed headers or non-Bearer schemes
 * - Input must be a string, otherwise returns null
 */
const parseAuthHeader = (headerValue: string): AuthHeader | null => {
  if (typeof headerValue !== 'string') {
    return null;
  }

  const parts = headerValue.split(' ');
  if (parts.length !== 2) {
    return null;
  }

  const [scheme, credentials] = parts;
  if (BEARER_SCHEME_REGEX.test(scheme)) {
    return { scheme, value: credentials };
  }

  return null;
};

export { parseAuthHeader as parse };
