# Security Policy

## Overview

Keycast is a hosted NIP-46 (Nostr remote signer) bunker service. We take security seriously and implement multiple layers of protection for your Nostr keys.

**For a comprehensive analysis of how Keycast compares to other Nostr key management solutions** (nsec.app, Amber, hardware wallets, etc.), see **[SECURITY_LADDER.md](./SECURITY_LADDER.md)** which provides an honest ranking of security levels and helps you choose the right solution for your needs.

## Security Model

### At Rest (Storage)
- ✅ **Keys encrypted** using GCP Cloud KMS with AES-256-GCM
- ✅ **Encrypted blobs** stored in PostgreSQL database
- ✅ **Database encrypted** at rest by Cloud Run infrastructure
- ✅ **KMS access controlled** via IAM with principle of least privilege

### In Transit
- ✅ **HTTPS/TLS 1.3** for all API communication
- ✅ **NIP-44 encryption** for bunker communication over Nostr relays
- ✅ **gRPC with mTLS** for KMS API calls

### Password Login Protection

Password login uses a tenant-scoped attempt budget shared by the web, OAuth popup, and
headless login endpoints. Repeated failures introduce an escalating delay and return `429`
with `Retry-After`; only failures in the latest 15-minute window contribute to the delay.
Successful login clears the budget. Completing the existing password reset flow also clears
it, providing recovery when a user cannot wait for the current delay. The limiter applies
the same response to registered and unregistered email addresses. Every attempt passes through
bcrypt CPU admission before the attempt reservation, and an unregistered address burns an
equivalent comparison, so a request shed by local overload does not consume the account's
budget and registration status is not distinguishable by response latency or in-flight
contention. A subject that is already limited keeps its `429` before admission. Login fails
closed with a retryable service-unavailable response when the shared Redis coordination store
is unavailable.

### In Memory (During Signing)
- ✅ **Immediate zeroization**: Keys zeroed from memory after each signing operation using `zeroize` crate
- ✅ **SecretVec wrapper**: Keys wrapped in secure containers that auto-zero on drop
- ✅ **Minimal exposure**: Keys decrypted only when needed for signing
- ⚠️ **Limitation**: Keys exist in application memory during signing operations (~milliseconds)

### Audit & Monitoring
- ✅ **All signing operations logged** with user pubkey, event kind, and timestamp
- ✅ **Security validation**: Pubkey mismatch detection (potential compromise indicator)
- ✅ **Cloud Audit Logs**: All KMS decrypt operations logged by GCP
- ✅ **Structured logging**: Easy to parse and alert on anomalies

## Known Limitations

### ⚠️ Memory Exposure Risk

**What**: Private keys exist in application memory during signing operations.

**Risk**: If an attacker gains ability to dump process memory, keys could be exposed.

**Mitigations in place**:
- Keys immediately zeroed after use
- SecretVec auto-zeroization on drop
- Container security (read-only filesystem, non-root user)
- Minimal IAM permissions
- Network isolation

**Residual risk**: Sophisticated memory dump attacks (requires server compromise)

### ⚠️ Not Recommended For

- ❌ High-value accounts (>$10,000 in associated Lightning/crypto wallets)
- ❌ Critical infrastructure keys
- ❌ Accounts requiring regulatory compliance (SOC2, PCI-DSS)
- ❌ Users in high-threat environments
- ❌ Users who cannot trust the service provider

**Alternative**: For maximum security, consider:
- **Client-side**: nsec.app (browser-based, non-custodial)
- **Mobile**: Amber (Android native, non-custodial)
- **Hardware**: Dedicated signing devices
- **Self-hosted**: Run your own Keycast instance

See [SECURITY_LADDER.md](./SECURITY_LADDER.md) for detailed comparison.

### ✅ Recommended For

- ✅ General social media posting on Nostr
- ✅ Team accounts requiring policy enforcement
- ✅ Low-to-medium value accounts
- ✅ Convenience over maximum security use cases
- ✅ Users who trust the service provider OR plan to self-host

## Future Enhancements

We are evaluating Hardware Security Module (HSM) integration for a premium tier that would provide additional security guarantees:
- Keys would never exist in application memory
- Signing would occur inside tamper-proof hardware (FIPS 140-2 Level 3)
- Increased cost (~$3-5/month per user vs current $0.10/month)

## Reporting a Vulnerability

**DO NOT report security vulnerabilities via GitHub Issues.**

Please email: security@keycast.example.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested mitigation (if any)

We will respond within 48 hours.

### Bug Bounty

We currently do not have a formal bug bounty program, but we appreciate responsible disclosure and will:
- Acknowledge your contribution
- Provide updates on fixes
- Credit you in our security hall of fame (with your permission)

## Incident Response

In the event of a security incident:

1. **Immediate Actions** (within 1 hour):
   - Rotate KMS encryption keys
   - Audit recent signing operations
   - Block suspicious IP addresses

2. **Investigation** (within 24 hours):
   - Identify scope of compromise
   - Determine affected users
   - Assess data exposure

3. **Notification** (within 72 hours):
   - Email affected users
   - Publish incident report
   - Provide remediation steps

4. **Long-term** (within 30 days):
   - Implement additional mitigations
   - External security audit
   - Update security documentation

## Security Best Practices for Users

1. **Enable 2FA** on your Keycast account
2. **Monitor activity** regularly via audit logs
3. **Use for appropriate use cases** (see recommendations above)
4. **Keep your bunker secret secure** - treat it like a password
5. **Report suspicious activity** immediately

## Compliance & Certifications

**Current status**:
- Infrastructure: GCP (SOC 2, ISO 27001 certified)
- KMS: FIPS 140-2 Level 3 certified
- Application: Security best practices, not formally audited yet

**Planned**:
- External security audit before public launch
- SOC 2 Type II certification (Year 2)
- Annual penetration testing

## Security Roadmap

**Q1 2025** (MVP):
- ✅ Memory zeroization (zeroize + secrecy)
- ✅ Audit logging
- ✅ Security documentation
- 🔄 External security audit
- 🔄 Automated security scanning (cargo audit in CI)

**Q2 2025** (Growth):
- Rate limiting and abuse detection
- Anomaly detection alerts
- User-facing security dashboard

**Q3 2025** (Scale):
- HSM integration for premium tier
- Bug bounty program
- SOC 2 compliance

## Contact

- **Security issues**: security@keycast.example.com
- **General inquiries**: contact@keycast.example.com
- **PGP Key**: [TBD]

---

**Last updated**: 2025-01-10
**Next review**: 2025-04-10
