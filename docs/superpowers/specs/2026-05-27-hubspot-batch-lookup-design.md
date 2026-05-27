# HubSpot Batch Lookup Endpoint Design

**Issue:** divinevideo/support-trust-safety#149
**Purpose:** Let divine-invite-sync enrich HubSpot contacts with Keycast account data so marketing can segment users from non-users.

## Background

Marketing (Alice) needs to know which HubSpot contacts have Divine accounts. The existing divine-invite-sync worker already syncs invite code claim status between invite-darshan and HubSpot. This extends it to also query Keycast for account data.

divine-invite-sync becomes a client to two upstream services: darshan for invite lifecycle, Keycast for account data.

## Endpoint

```
POST /api/admin/users/batch-lookup
Authorization: Bearer <KEYCAST_SERVICE_TOKEN>
Content-Type: application/json
```

### Request

```json
{
  "emails": ["alice@example.com", "Bob@Example.COM", "unknown@test.com"]
}
```

- Maximum 1000 emails per request (400 if exceeded)
- Server-side deduplication and lowercase normalization before querying
- Empty array is valid (returns 200 with empty results)

### Response

```json
{
  "results": {
    "alice@example.com": {
      "email": "alice@example.com",
      "pubkey": "ab12...64hex",
      "status": "active",
      "email_verified": true,
      "has_personal_key": true,
      "created_at": "2026-01-15T10:30:00+00:00"
    },
    "bob@example.com": {
      "email": "Bob@Example.COM",
      "pubkey": "cd34...64hex",
      "status": "suspended",
      "email_verified": true,
      "has_personal_key": false,
      "created_at": "2026-03-20T14:00:00+00:00"
    }
  },
  "not_found": ["unknown@test.com"]
}
```

- `results` keyed by lowercase email for consistent caller lookup
- `email` field in each result preserves original case from database
- `not_found` contains deduplicated, lowercased input emails that didn't match
- Suspended/banned users are included (marketing needs them for suppression)
- `status` values: `active`, `suspended`, `banned`

### Error Responses

- 400: `emails` array exceeds 1000 elements
- 401: Missing or invalid `Authorization` header
- 500: `KEYCAST_SERVICE_TOKEN` not configured

## Auth

Uses existing `authorize_service_token()` (admin.rs:1811-1837) -- constant-time blake3 comparison against `KEYCAST_SERVICE_TOKEN` env var. Same pattern as `/api/admin/users/:pubkey/status` used by relay-manager.

Wired into `service_admin_routes` in routes.rs -- no CORS layer (server-to-server only).

## Data Layer

New method on `UserRepository`:

```rust
pub async fn find_users_by_emails(
    &self,
    emails: &[String],
    tenant_id: i64,
) -> Result<Vec<AdminUserDetails>, RepositoryError>
```

- Single SQL query: `WHERE LOWER(u.email) = ANY($1::text[]) AND u.tenant_id = $2`
- LEFT JOIN on `personal_keys` for `has_personal_key` (same pattern as `find_users_for_admin`)
- Reuses existing `AdminUserDetails` struct -- no new types in core
- Hits existing `idx_users_email_tenant` unique index
- Empty input short-circuits to `Ok(vec![])` without querying

No schema changes, no new indexes, no migrations.

## Files Changed

| Action | File | What |
|--------|------|------|
| Modify | `core/src/repositories/user.rs` | Add `find_users_by_emails()` |
| Modify | `api/src/api/http/admin.rs` | Add types + handler |
| Modify | `api/src/api/http/routes.rs` | Wire into `service_admin_routes` |
| Create | `api/tests/batch_lookup_test.rs` | Integration tests |

## Tests

11 integration tests following the `user_status_admin_test.rs` pattern:

| # | Test | What it catches |
|---|------|----------------|
| 1 | Returns matching user with correct fields | Basic contract |
| 2 | Mixed batch: some found, some not_found | Production call pattern |
| 3 | All unknown emails → empty results, all in not_found | Empty-match path |
| 4 | Duplicate emails deduplicated in response | Server-side dedup contract |
| 5 | Over 1000 emails returns 400 | Input validation |
| 6 | Missing auth header → 401 | Auth gate |
| 7 | Wrong token → 401 | Auth gate |
| 8 | Empty emails array → 200 with empty results | Edge case |
| 9 | Case-insensitive email matching | Normalization |
| 10 | Suspended user returned with correct status | Status accuracy for suppression |
| 11 | `has_personal_key` true vs false in same batch | LEFT JOIN correctness |

## Explicitly Not Doing

- **Change-feed endpoint** (`GET /enrichment-feed?since=<timestamp>`): needed when re-enriching 200K+ contacts for status changes is too slow via sweep. Requires a new index on `users(tenant_id, updated_at)` which doesn't exist today. Future work per issue #149.
- **Activity/engagement fields** (last_active, active_sessions, username): Tier 3 enrichment, additive when marketing needs engagement-based segmentation.
- **divine-invite-sync integration**: separate PR in a separate repo. This PR is Keycast-only.
