# passport-jose

[![npm version](https://badge.fury.io/js/passport-jose.svg)](https://www.npmjs.com/package/passport-jose)
[![Node.js CI](https://github.com/asyne/passport-jose/actions/workflows/ci.yml/badge.svg)](https://github.com/asyne/passport-jose/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/asyne/passport-jose/graph/badge.svg)](https://codecov.io/gh/asyne/passport-jose)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern, security-focused [Passport](http://passportjs.org/) strategy for authenticating with [JSON Web Tokens](https://jwt.io) using the [jose](https://github.com/panva/jose) library.

This package is a complete TypeScript rewrite focused on Bearer token authentication with enhanced security through the modern `jose` library. It's designed to secure API endpoints without sessions.

## Table of Contents

- [Key Features](#key-features) - What makes passport-jose unique
- [Installation](#installation) - Add to your project
- [Quick Start](#quick-start) - Get running in 2 minutes
- [Basic Usage](#basic-usage) - Essential configuration and setup
  - [Configure Strategy](#configure-strategy)
  - [Example Configuration](#example-configuration)
  - [Using Different Key Formats](#using-different-key-formats)
  - [JWT Extraction Methods](#jwt-extraction-methods)
  - [Authenticate Requests](#authenticate-requests)
  - [Include JWT in Requests](#include-jwt-in-requests)
- [Framework Integration](#framework-integration) - Use with popular frameworks
  - [NestJS Integration](#nestjs-integration)
  - [Express.js Integration](#expressjs-integration)
  - [GraphQL Integration](#graphql-integration)
- [Advanced Topics](#advanced-topics) - Production features and customization
  - [Remote JWKS Integration](#remote-jwks-integration)
    - [Basic JWKS Usage](#basic-jwks-usage)
    - [Popular Identity Provider Configurations](#popular-identity-provider-configurations)
    - [JWKS Configuration Options](#jwks-configuration-options)
  - [Multi-tenant Support](#multi-tenant-support)
  - [EdDSA Keys](#eddsa-keys)
  - [Custom JWT Extractors](#custom-jwt-extractors)
- [Migration from passport-jwt](#migration-from-passport-jwt) - Upgrade guide
- [Troubleshooting](#troubleshooting) - Common issues and solutions
- [API Reference](#api-reference) - Complete API documentation
- [Security Considerations](#security-considerations) - Production security best practices
- [Development](#development) - Build and contribute
- [License](#license)
- [Credits](#credits)

## Key Features

- **Enhanced Security**: Uses the modern [jose](https://github.com/panva/jose) library (v6+) with support for modern algorithms like **EdDSA**
- **Bearer Token Focused**: Exclusively supports RFC 6750 Bearer token authentication
- **Full TypeScript**: Complete TypeScript implementation with strict typing
- **Modern Standards**: Built for ES2023 with latest JavaScript features
- **Native Key Support**: Supports CryptoKey, KeyObject, JWK, and Uint8Array formats natively
- **Performance**: Optimized JWT verification using native crypto APIs and minimal dependencies
- **Lightweight**: Minimal bundle footprint with only essential dependencies (`jose` + `passport-strategy`)
- **Multi-tenant Ready**: Dynamic key resolution for enterprise applications

## Installation

```bash
# npm
$ npm install passport-jose

# pnpm
$ pnpm add passport-jose

# yarn
$ yarn add passport-jose
```

## Quick Start

Get up and running with `passport-jose` in under 2 minutes:

```typescript
import passport from 'passport';
import { Strategy, ExtractJwt } from 'passport-jose';

// 1. Configure the strategy
const secretKey = new TextEncoder().encode('your-256-bit-secret');

passport.use(new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withSecretOrKey: secretKey,
  algorithms: ['HS256']
}, (payload, done) => {
  // 2. Verify the user
  const user = { id: payload.sub, email: payload.email };
  done(null, user);
}));

// 3. Protect your routes
app.get('/profile',
  passport.authenticate('jwt', { session: false }),
  (req, res) => res.json({ user: req.user })
);
```

Send requests with the JWT in the Authorization header:
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:3000/profile
```

## Basic Usage

### Configure Strategy

The JWT authentication strategy is constructed as follows:

```typescript
import { Strategy, ExtractJwt, type JoseKey } from 'passport-jose';

new Strategy(options, verify)
```

`options` is an object containing configuration for token extraction and verification:

* `withSecretOrKey` - JOSE-compatible key for JWT verification (CryptoKey, KeyObject, JWK, or Uint8Array). **REQUIRED** unless `withKeyProvider` is provided.
* `withKeyProvider` - Dynamic key resolution callback: `(request, rawJwtToken, done) => void` where `done` has signature `(err: Error | string | null, key?: JoseKey) => void`. **REQUIRED** unless `withSecretOrKey` is provided.
* `jwtFromRequest` - (**REQUIRED**) Function that extracts the JWT from the request: `(req) => string | null`
* `issuer` - Expected JWT "iss" (Issuer) claim value(s). Makes the claim presence required.
* `audience` - Expected JWT "aud" (Audience) claim value(s). Makes the claim presence required.
* `algorithms` - List of accepted JWS "alg" values (e.g., `["HS256", "RS256"]`)
* `subject` - Expected JWT "sub" (Subject) claim value. Makes the claim presence required.
* `maxTokenAge` - Maximum time elapsed from JWT "iat" claim (e.g., `"1h"`, `3600`)
* `clockTolerance` - Clock skew tolerance for time-based claims (e.g., `"30s"`, `30`)
* `typ` - Expected JWT "typ" (Type) header parameter value
* `passReqToCallback` - If `true`, request is passed to verify callback as first argument

`verify` is a function with the parameters `verify(jwt_payload, done)` or `verify(req, jwt_payload, done)` if `passReqToCallback: true`

### Example Configuration

```typescript
import passport from 'passport';
import { Strategy, ExtractJwt, type JoseKey } from 'passport-jose';

// Using a symmetric key (Uint8Array)
const secretKey: JoseKey = new TextEncoder().encode('your-256-bit-secret');

const options = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withSecretOrKey: secretKey,
  algorithms: ['HS256'],
  issuer: 'accounts.examplesoft.com',
  audience: 'yoursite.net'
};

passport.use(new Strategy(options, (payload, done) => {
  // payload is typed as jose.JWTPayload
  // Note: User.findOne is pseudo-code - replace with your user lookup logic
  User.findOne({ id: payload.sub }, (err, user) => {
    if (err) return done(err, false);
    if (user) return done(null, user);
    return done(null, false);
  });
}));
```

### Using Different Key Formats

```typescript
// JWK format
const jwkKey: JoseKey = {
  kty: 'RSA',
  use: 'sig',
  n: '...',
  e: 'AQAB'
};

// Web Crypto API key
const cryptoKey: JoseKey = await crypto.subtle.importKey(/* ... */);

// Node.js KeyObject
const keyObject: JoseKey = crypto.createSecretKey(Buffer.from('secret'));
```

### JWT Extraction Methods

The JWT must be extracted from the request using a user-supplied extractor function passed as the `jwtFromRequest` parameter.

#### Included Extractors

* `ExtractJwt.fromHeader(header_name)` - Extracts JWT from the specified HTTP header
* `ExtractJwt.fromBodyField(field_name)` - Extracts JWT from the request body field
* `ExtractJwt.fromAuthHeaderAsBearerToken()` - Extracts JWT from Authorization header with Bearer scheme (**recommended**)
* `ExtractJwt.fromExtractors([extractors])` - Tries multiple extractors in sequence

#### Custom Extractor Example

```typescript
const cookieExtractor = (req: any): string | null => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
  }
  return token;
};

const options = {
  jwtFromRequest: cookieExtractor,
  withSecretOrKey: secretKey
};
```

### Authenticate Requests

Use `passport.authenticate()` specifying `'jwt'` as the strategy:

```typescript
app.post('/profile',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.send(req.user.profile);
  }
);
```

### Include JWT in Requests

When using `ExtractJwt.fromAuthHeaderAsBearerToken()`, include the JWT in the Authorization header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Advanced Topics

### Remote JWKS Integration

```typescript
import { Strategy, ExtractJwt, fromRemoteJwks } from 'passport-jose';

// Auth0 JWKS integration
const auth0Strategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://dev-example.auth0.com/.well-known/jwks.json', {
    cacheMaxAge: 600000, // 10 minutes
    cooldownDuration: 30000, // 30 seconds
  }),
  algorithms: ['RS256'],
  issuer: 'https://dev-example.auth0.com/',
  audience: 'https://api.myapp.com'
}, (payload, done) => {
  User.findById(payload.sub, done);
});

// Azure AD JWKS integration
const azureStrategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://login.microsoftonline.com/tenant/discovery/v2.0/keys', {
    cacheMaxAge: 300000, // 5 minutes
    timeoutDuration: 10000 // 10 seconds
  }),
  algorithms: ['RS256'],
  issuer: 'https://login.microsoftonline.com/tenant/v2.0'
}, (payload, done) => {
  User.findById(payload.sub || payload.oid, done);
});
```

#### Basic JWKS Usage

```typescript
import { Strategy, ExtractJwt, fromRemoteJwks } from 'passport-jose';

// Auth0 integration
const strategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://your-domain.auth0.com/.well-known/jwks.json', {
    cacheMaxAge: 600000, // 10 minutes
    cooldownDuration: 30000, // 30 seconds between requests
    timeoutDuration: 5000, // 5 seconds request timeout
  }),
  algorithms: ['RS256'],
  issuer: 'https://your-domain.auth0.com/',
  audience: 'your-api-identifier'
}, (payload, done) => {
  User.findById(payload.sub, done);
});
```

#### Popular Identity Provider Configurations

```typescript
// Example verify function (implement according to your user model)
const verifyUser = (payload, done) => {
  User.findById(payload.sub, (err, user) => {
    if (err) return done(err, false);
    if (user) return done(null, user);
    return done(null, false);
  });
};

// Auth0
const auth0Strategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://dev-example.auth0.com/.well-known/jwks.json', {
    cacheMaxAge: 600000,
    cooldownDuration: 30000,
  }),
  algorithms: ['RS256'],
  issuer: 'https://dev-example.auth0.com/',
  audience: 'https://api.myapp.com'
}, verifyUser);

// Azure Active Directory
const azureStrategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://login.microsoftonline.com/common/discovery/v2.0/keys', {
    cacheMaxAge: 300000, // 5 minutes (Azure keys rotate frequently)
    timeoutDuration: 10000,
  }),
  algorithms: ['RS256'],
  issuer: 'https://login.microsoftonline.com/{tenant}/v2.0'
}, verifyUser);

// AWS Cognito
const cognitoStrategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json', {
    cacheMaxAge: 3600000, // 1 hour
    cooldownDuration: 60000,
  }),
  algorithms: ['RS256'],
  issuer: 'https://cognito-idp.{region}.amazonaws.com/{userPoolId}'
}, verifyUser);

// Google Identity Platform
const googleStrategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: fromRemoteJwks('https://www.googleapis.com/oauth2/v3/certs', {
    cacheMaxAge: 86400000, // 24 hours
    cooldownDuration: 30000,
  }),
  algorithms: ['RS256'],
  issuer: 'https://accounts.google.com'
}, verifyUser);
```

#### JWKS Configuration Options

```typescript
interface RemoteJWKSetOptions {
  /**
   * Duration for which the JWKS is cached (default: 600000ms / 10 minutes)
   */
  cacheMaxAge?: number;

  /**
   * Cooldown period between JWKS requests (default: 30000ms / 30 seconds)
   */
  cooldownDuration?: number;

  /**
   * HTTP request timeout for JWKS fetching (default: 5000ms / 5 seconds)
   */
  timeoutDuration?: number;

  /**
   * HTTP agent for custom connection handling
   */
  agent?: any;

  /**
   * Additional headers to include in JWKS requests
   */
  headers?: Record<string, string>;
}
```

### Multi-tenant Support

```typescript
import { Strategy, ExtractJwt, type SecretOrKeyProvider } from 'passport-jose';
import { decodeProtectedHeader } from 'jose';

const keyProvider: SecretOrKeyProvider = (request, rawJwtToken, done) => {
  // Extract tenant from JWT header or request
  const decoded = decodeProtectedHeader(rawJwtToken);
  const tenantId = decoded.kid || request.headers['x-tenant-id'];

  // Fetch tenant-specific key
  getTenantKey(tenantId)
    .then(key => done(null, key))
    .catch(err => done(err));
};

const strategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withKeyProvider: keyProvider,
  algorithms: ['RS256', 'ES256'],
  issuer: 'https://auth.myapp.com'
}, (payload, done) => {
  // Verify user with tenant context
  User.findInTenant(payload.tenant, payload.sub, done);
});
```

### EdDSA Keys

```typescript
import { generateKeyPair } from 'crypto';
import { Strategy, ExtractJwt } from 'passport-jose';

// Generate EdDSA key pair
const { publicKey, privateKey } = generateKeyPair('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const strategy = new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withSecretOrKey: publicKey,
  algorithms: ['EdDSA']
}, (payload, done) => {
  User.findById(payload.sub, done);
});
```

### Custom JWT Extractors

```typescript
const cookieExtractor = (req: any): string | null => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
  }
  return token;
};

const options = {
  jwtFromRequest: cookieExtractor,
  withSecretOrKey: secretKey
};
```

## Framework Integration

### NestJS Integration

Here's how to integrate `passport-jose` with NestJS:

```typescript
// auth/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, ExtractJwt, fromRemoteJwks } from 'passport-jose';

const CACHE_MAX_AGE = 600_000; // 10 minutes

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    const jwksUrl = configService.get<string>('IDENTITY_PROVIDER_URL') + '/.well-known/jwks.json';

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      withKeyProvider: fromRemoteJwks(jwksUrl, { cacheMaxAge: CACHE_MAX_AGE }),
      algorithms: ['RS256'],
      issuer: configService.get<string>('JWT_ISSUER'),
      audience: configService.get<string>('JWT_AUDIENCE'),
    });
  }

  validate({ sub, email }: { sub: string; email: string }) {
    return { userId: sub, email };
  }
}

// auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';

@Module({
  providers: [JwtStrategy],
})
export class AuthModule {}

// types/express.d.ts - Type augmentation for Express
declare namespace Express {
  namespace Request {
    interface User {
      userId: string;
      email: string;
    }
  }

  interface Request {
    user?: Request.User;
  }
}

type ContextUser = Express.Request.User;

// middleware/auth/auth.guard.ts - HTTP Authentication Guards
import { Injectable, ExecutionContext, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class HttpAuthGuard extends AuthGuard('jwt') {
  getRequest(context: ExecutionContext) {
    return context.switchToHttp().getRequest();
  }
}

@Injectable()
export class HttpOptionalAuthGuard extends HttpAuthGuard {
  handleRequest<TUser>(err: any, user: TUser): TUser | null {
    if (err) {
      throw err;
    }
    return user;
  }
}

// Guard Decorators
export const WithAuth = UseGuards(HttpAuthGuard);
export const WithOptionalAuth = UseGuards(HttpOptionalAuthGuard);

// middleware/auth/current-user.decorator.ts - Current user decorator
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (_: unknown, context: ExecutionContext): ContextUser => {
    return context.switchToHttp().getRequest().user;
  },
);

// app.controller.ts - Example HTTP Controller Usage
import { Controller, Get } from '@nestjs/common';
import { WithAuth, WithOptionalAuth } from './middleware/auth/auth.guard';
import { CurrentUser } from './middleware/auth/current-user.decorator';

@Controller('api')
export class AppController {
  @Get('profile')
  @WithAuth
  getProfile(@CurrentUser() user: ContextUser) {
    return {
      message: 'Protected route',
      user,
    };
  }

  @Get('dashboard')
  @WithOptionalAuth
  getDashboard(@CurrentUser() user: ContextUser | null) {
    return {
      message: user ? 'Authenticated dashboard' : 'Public dashboard',
      user,
    };
  }

  @Get('public')
  getPublic() {
    return { message: 'Public route' };
  }
}

// app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { AppController } from './app.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
  ],
  controllers: [AppController],
})
export class AppModule {}
```

**Environment variables (.env):**
```env
IDENTITY_PROVIDER_URL=https://auth.example.com
JWT_ISSUER=https://auth.example.com
JWT_AUDIENCE=my-api
```

**Migration from `@nestjs/passport` + `passport-jwt`:**

1. Replace `passport-jwt` with `passport-jose`
2. Update strategy options: `secretOrKey` → `withSecretOrKey`
3. Consider using `fromRemoteJwks()` for better key management
4. Add required `algorithms` array
5. Replace `ignoreExpiration` with `maxTokenAge` if needed

### Express.js Integration

```typescript
import express from 'express';
import passport from 'passport';
import { Strategy, ExtractJwt } from 'passport-jose';

const app = express();

passport.use('jwt', new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withSecretOrKey: new TextEncoder().encode(process.env.JWT_SECRET),
  algorithms: ['HS256'],
  issuer: process.env.JWT_ISSUER,
  maxTokenAge: '1h'
}, async (payload, done) => {
  try {
    const user = await User.findById(payload.sub);
    if (!user) return done(null, false, { message: 'User not found' });
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Protected route with custom error handling
app.get('/api/profile',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.json({ user: req.user });
  }
);

// Custom error handler for JWT failures
app.use((err, req, res, next) => {
  if (err.name === 'JWTInvalid' || err.name === 'JWTExpired') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  next(err);
});
```

### GraphQL Integration

```typescript
import { ApolloServer } from 'apollo-server-express';
import passport from 'passport';
import { Strategy, ExtractJwt } from 'passport-jose';

passport.use(new Strategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  withSecretOrKey: new TextEncoder().encode(process.env.JWT_SECRET),
  algorithms: ['HS256']
}, (payload, done) => {
  User.findById(payload.sub, done);
}));

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => {
    return new Promise((resolve, reject) => {
      passport.authenticate('jwt', { session: false }, (err, user) => {
        if (err) return reject(err);
        resolve({ user, req });
      })(req);
    });
  }
});
```

## Migration from passport-jwt

This library is **not** a drop-in replacement for passport-jwt. Key differences:

### What's Changed
- **Property Names**: `secretOrKey` → `withSecretOrKey`, `secretOrKeyProvider` → `withKeyProvider`
- **Library**: Uses `jose` library instead of `jsonwebtoken`
- **Authentication**: Only supports Bearer token authentication
- **Expiration**: Removed `ignoreExpiration` option (use `maxTokenAge` instead)
- **Headers**: Removed `fromAuthHeaderWithScheme` (use Bearer tokens only)
- **Keys**: Different key format support (`jose` native types)
- **JWKS**: Added remote JWKS support with `fromRemoteJwks()`

### Migration Steps
1. **Update imports**: `passport-jwt` → `passport-jose`
2. **Update property names**:
   - `secretOrKey` → `withSecretOrKey`
   - `secretOrKeyProvider` → `withKeyProvider`
3. **Convert keys** to `jose`-compatible formats (CryptoKey, KeyObject, JWK, Uint8Array)
4. **Replace options**:
   - `ignoreExpiration` → `maxTokenAge`
   - Add required `algorithms` array
5. **Use Bearer extraction**: `ExtractJwt.fromAuthHeaderAsBearerToken()`
6. **Add JWKS support**: Consider using `fromRemoteJwks()` for production
7. **Update TypeScript types**: Import types from `passport-jose`

## Troubleshooting

### Common Issues

#### "Invalid JWT" errors
- Ensure your JWT token is properly formatted and signed with the correct key
- Verify that the algorithm specified in `algorithms` array matches the JWT's signing algorithm
- Check that the JWT hasn't expired (use `maxTokenAge` to control this)

#### "No auth token" errors
- Verify that your `jwtFromRequest` extractor is correctly configured
- For Bearer tokens, ensure the Authorization header format is: `Authorization: Bearer <token>`
- Check that the token is being included in the request

#### Type errors with keys
```typescript
// ❌ Wrong - raw string
withSecretOrKey: 'my-secret'

// ✅ Correct - Uint8Array for symmetric keys
withSecretOrKey: new TextEncoder().encode('my-secret')

// ✅ Correct - for asymmetric keys
withSecretOrKey: fs.readFileSync('public-key.pem')

// ✅ Best - JWKS for production
withKeyProvider: fromRemoteJwks('https://auth.example.com/.well-known/jwks.json', {
  cacheMaxAge: 600000
})
```

#### Claims validation failures
- When using `issuer`, `audience`, or `subject` options, ensure your JWTs include these claims
- Use `clockTolerance` option if you're experiencing time-related validation issues

### Debugging Tips

1. **Enable debug logging**: Set `DEBUG=passport-jose:*` environment variable
2. **Test JWT tokens**: Use [jwt.io](https://jwt.io) to decode and verify your tokens
3. **Check extractor**: Test your `jwtFromRequest` function independently:
   ```typescript
   const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
   console.log('Extracted token:', token);
   ```
4. **Validate keys**: Ensure your signing and verification keys match:
   ```typescript
   // For symmetric keys, both should be identical
   const signingKey = new TextEncoder().encode('secret');
   const verificationKey = new TextEncoder().encode('secret');

   // For asymmetric keys, public key verifies what private key signed
   ```
5. **Check claims**: Log the payload in your verify callback:
   ```typescript
   passport.use(new Strategy(options, (payload, done) => {
     console.log('JWT Payload:', payload);
     // ... rest of verification
   }));
   ```

### Environment-Specific Issues

#### Development vs Production
- Development: Consider using longer `maxTokenAge` for easier testing
- Production: Use shorter expiration times and implement refresh token patterns

#### CORS and Preflight Requests
- Ensure your CORS configuration allows Authorization headers
- Preflight OPTIONS requests don't include Authorization headers

#### Load Balancers and Proxies
- Verify that Authorization headers are forwarded correctly
- Some load balancers may strip or modify headers

## API Reference

### Strategy Options

```typescript
interface StrategyOptions {
  jwtFromRequest: JwtFromRequestFunction;
  withSecretOrKey?: JoseKey;
  withKeyProvider?: SecretOrKeyProvider;
  issuer?: string | string[];
  audience?: string | string[];
  algorithms?: string[];
  subject?: string;
  maxTokenAge?: string | number;
  clockTolerance?: string | number;
  typ?: string;
  passReqToCallback?: boolean;
}
```

### Type Definitions

```typescript
import type { CryptoKey, KeyObject, JWK, JWTVerifyGetKey } from 'jose';

// Re-exported `jose` types
type JoseKey = CryptoKey | KeyObject | JWK | Uint8Array;

interface JwtFromRequestFunction<T = any> {
  (req: T): string | null;
}

interface SecretOrKeyProvider<T = any> {
  (request: T, rawJwtToken: string, done: (err: Error | string | null, secretOrKey?: JoseKey | JWTVerifyGetKey) => void): void;
}

// JWKS Provider function
function fromRemoteJwks(
  jwksUri: string,
  options: RemoteJWKSetOptions
): SecretOrKeyProvider;
```

## Development

### Build and Test

```bash
# Install dependencies
yarn install

# Build TypeScript
yarn build

# Run tests
yarn test

# Run tests with coverage
yarn test:coverage
```

### Requirements

- Node.js 20+ (minimum required version)
- TypeScript 5.0+ for development

### Performance Characteristics

- **JWT Verification**: ~10-50μs per token (varies by algorithm and key type)
- **JWKS Caching**: Configurable cache reduces remote key fetches
- **Memory Usage**: Minimal overhead with efficient key caching
- **Bundle Size**: ~150KB total (including dependencies)

### Compatibility

- **Node.js**: 20.0.0+
- **TypeScript**: 5.0+
- **Passport**: 0.4.0+
- **JOSE Library**: 6.0.0+

## Security Considerations

### Production Best Practices

- **HTTPS Only**: Always use HTTPS in production to prevent token interception
- **Strong Secrets**: Use cryptographically strong, randomly generated secrets (minimum 256 bits for HS256)
- **Key Rotation**: Implement regular key rotation strategies, especially for symmetric keys
- **Token Expiration**: Set appropriate token expiration times with `maxTokenAge` (recommend 15-60 minutes for access tokens)
- **Algorithm Whitelist**: Always specify the `algorithms` array to prevent algorithm confusion attacks
- **Claim Validation**: Validate all JWT claims that are relevant to your application security model

### Key Management

```typescript
// ✅ Good: Use strong, randomly generated secrets
const secret = crypto.randomBytes(32); // 256 bits

// ✅ Better: Use asymmetric keys for distributed systems
const { publicKey, privateKey } = generateKeyPair('ed25519');

// ✅ Best: Use JWKS for production environments
withKeyProvider: fromRemoteJwks('https://auth.example.com/.well-known/jwks.json')
```

### Common Security Vulnerabilities

- **Algorithm Confusion**: Prevented by specifying `algorithms` array
- **Key Confusion**: Use different keys for different purposes
- **Timing Attacks**: The `jose` library provides constant-time comparisons
- **Token Replay**: Consider implementing nonce/jti claims for critical operations

### Monitoring and Logging

- Log authentication failures for security monitoring
- Monitor for unusual token usage patterns
- Set up alerts for JWKS endpoint failures
- Track token expiration and refresh patterns

## License

The [MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2025 asyne

## Credits

This project is inspired by and builds upon the excellent work of [Mike Nicholson](https://github.com/mikenicholson) and the original [passport-jwt](https://github.com/mikenicholson/passport-jwt) library. We're grateful for the foundation provided by the original passport-jwt project.
