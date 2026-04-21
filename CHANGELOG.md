# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Multi-Tenancy Infrastructure (In Progress)**: Domain-based tenant isolation for running keycast at multiple domains
  - Database migration adding `tenants` table and `tenant_id` to all tables
  - Tenant resolution middleware (extracts tenant from Host header)
  - Tenant management CLI (`scripts/manage-tenants.sh`)
  - Research documents: architecture patterns, database options, query audit, implementation plan
  - Decision: Stay on SQLite (sufficient for current scale), migrate to PostgreSQL at 1,000+ users
- **Single Relay Subscription Architecture**: Optimized signer daemon to use ONE subscription for ALL kind 24133 events instead of one per user. Scales to millions of users with just 3 relay connections.
- **Fast Reload Optimization**: Only decrypt last 5 new authorizations instead of all keys. Reduced reload time from 18-21 seconds to ~1.5 seconds.
- **Comprehensive Technical Documentation**: Added `/docs` endpoint with deep dive into architecture, NIP-46, OAuth flow, encryption, relay architecture, and security model.
- **Improved Landing Page**: Rewrote landing page with simple, non-technical language focused on user value. Added clear explanation of how Keycast works like Bluesky (custodial, easy to use).
- **Static File Serving**: Added `/examples/*` route to serve test client HTML files directly from login.divine.video.
- **Multi-Relay Redundancy**: Connect to 3 relays (relay.damus.io, nos.lol, relay.nsec.app) for high availability.

### Changed
- **Relay Architecture**: Refactored from per-user subscriptions to single global subscription with in-memory filtering by bunker pubkey.
- **Landing Page Content**: Simplified above-the-fold messaging to focus on ease of use rather than technical details. Technical content moved to `/docs`.
- **Landing Page Links**: Updated all example client links to use https://login.divine.video instead of localhost.
- **NIP-05 Discovery Response Shape (PR #72)**: Documented that `GET /.well-known/nostr.json` without a `name` query returns `names: {}` alongside existing `nip46` discovery fields. This is a non-breaking additive response-field change for clients that ignore unknown fields.

### Performance
- **Signer daemon**: Single kind 24133 subscription for all 74+ users (was 74+ separate subscriptions)
- **Reload time**: 1.5 seconds (was 18-21 seconds)
- **Relay connections**: 3 total regardless of user count (was 3 × number of users)
- **Memory usage**: O(n) HashMap lookup vs O(n) subscription management

### Technical Details
- Signer daemon now filters events in handler by checking `#p` tag against managed bunker pubkeys
- Fast reload only decrypts last 5 authorization IDs (new registrations are sequential)
- GCP KMS decryption performance: ~300ms per key
- Event handler silently ignores kind 24133 events for non-managed bunkers

## [0.2.0] - 2025-01-12

### Added
- Dual NIP-04/NIP-44 encryption support in signer daemon with automatic fallback
- Immediate signer reload signal mechanism via `.reload_signal` file for faster OAuth onboarding
- OAuth + NIP-46 signing test clients (NDK and nostr-tools versions)
- Working OAuth sign test client demonstrating complete flow
- Manual bunker test client for debugging NIP-46 connections
- Comprehensive project documentation:
  - `DEVELOPMENT.md` - Local testing and deployment guide
  - `ISSUES.md` - Production readiness tracking (26 issues catalogued)
  - `MONITORING.md` - Cloud logging and error monitoring setup
  - `SECURITY.md` - Security model, limitations, and best practices
- Docker Compose dev environment configuration

### Changed
- Signer daemon now tries NIP-44 encryption first, falls back to NIP-04 for backward compatibility
- OAuth token endpoint triggers immediate signer reload instead of waiting for polling cycle
- Enhanced OAuth test clients with better error handling and debug output
- Response encryption matches request encryption method (NIP-44 or NIP-04)

### Fixed
- NIP-46 signer compatibility with clients using different encryption standards
- OAuth authorization flow now properly returns authorization codes
- Signer daemon reload latency reduced from ~10 seconds to <100ms

### Documentation
- Personal authentication system with email/password registration and login
- UCAN-based authentication with 24-hour token expiration
- Automatic login after registration (returns UCAN token immediately)
- NIP-46 bunker URL generation for registered users
- Database migrations for personal authentication (email, password_hash, personal_keys table)
- GCP KMS integration for encrypting user secret keys
- CORS configuration allowing all origins for embeddable authentication flows
- Test client HTML page for demonstrating auth flow
- OAuth authorization flow with NIP-46 remote signing
- Unified signer daemon architecture handling all bunker URLs in single process
- OAuthAuthorization type in core for managing OAuth-based remote signing
- Database migration for OAuth authorizations table with proper schema
- Three new API endpoints:
  - `POST /api/auth/register` - Register new user with email/password (auto-login)
  - `POST /api/auth/login` - Login existing user
  - `GET /api/user/bunker` - Get NIP-46 bunker URL (requires authentication)

### Changed
- Updated CORS from single origin to allow all origins for embeddable auth
- Registration endpoint now returns UCAN token for seamless user experience
- **BREAKING**: Refactored signer from multi-process (one per authorization) to unified single-process architecture
- OAuth authorizations now use user's personal key instead of generating random keys
- OAuth bunker URLs use user's public key as bunker_public_key with unique connection secret per app
- Signer now handles both regular and OAuth authorizations in single unified process with routing by bunker_pubkey

### Security
- Passwords hashed with bcrypt (DEFAULT_COST)
- User secret keys encrypted with GCP KMS or file-based key manager
- UCAN tokens for secure session management
- Unique bunker secrets (64-character alphanumeric) for NIP-46 connections
- OAuth authorizations support per-app revocation via unique bunker URL per app
