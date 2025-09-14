# Security Policy

## Supported Versions

The following versions of passport-jose are currently supported with security updates.

| Version | Supported          | End-of-life |
| ------- | ------------------ | ----------- |
| > 0.3.0 | :white_check_mark: | TBD         |

End-of-life for the current release will be determined prior to the release of its successor.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in passport-jose, please report it responsibly.

### How to Report

You should report vulnerabilities using the [GitHub Security Advisory interface](https://github.com/asyne/passport-jose/security/advisories/new) or by emailing the maintainers directly.

### What to Include

When reporting a vulnerability, please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact and attack scenarios
- Any suggested fixes or mitigations
- Your contact information for follow-up

### Response Timeline

- **Initial Response**: We aim to acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability within 5 business days
- **Resolution**: Critical vulnerabilities will be addressed with high priority, typically within 2 weeks
- **Disclosure**: We follow responsible disclosure practices and will coordinate with you on timing

### Security Considerations

`passport-jose` depends on the following security-critical libraries:
- [`jose`](https://github.com/panva/jose) - For JWT verification and cryptographic operations
- [`passport-strategy`](https://github.com/jaredhanson/passport-strategy) - Base strategy implementation

Security issues in these dependencies should also be reported to their respective maintainers.

## Security Best Practices

When using `passport-jose` in production:

- Always use HTTPS to prevent token interception
- Use strong, randomly generated secrets (minimum 256 bits for symmetric keys)
- Implement proper key rotation strategies
- Set appropriate token expiration times with `maxTokenAge`
- Always specify the `algorithms` array to prevent algorithm confusion attacks
- Validate all JWT claims relevant to your security model
- Use JWKS endpoints for dynamic key management in production
- Monitor and log authentication failures
- Keep dependencies up to date

For more detailed security guidance, see the [Security Considerations](https://github.com/asyne/passport-jose#security-considerations) section in our README.
