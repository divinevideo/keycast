# Local hosted-group demonstration

The executable acceptance test is [e2e/scripts/group-flow.mjs](../e2e/scripts/group-flow.mjs). It uses normal account registration and email verification, authenticated group HTTP routes, and encrypted NIP-46 request/reply events through a real relay. It does not seed database rows or call a handler directly.

## Run against disposable local services

Prepare a dedicated local Postgres database with all migrations, local Redis, and the development master key. Keep that key available for the server's hosted-key encryption. Build the normal server binary and install the existing E2E dependencies:

```sh
cargo build --bin keycast
bun run key:generate
(cd e2e && bun install --frozen-lockfile)
```

Start a separate local relay in one terminal; change the port if it is occupied:

```sh
nak serve --hostname 127.0.0.1 --port 60221
```

In another terminal, set `GROUP_DEMO_DATABASE_URL` and `GROUP_DEMO_REDIS_URL` to the disposable local services, then start the normal server from the repository root. This uses the synthetic development server key already used by the repository's development scripts. An empty email-provider key selects the development inbox.

```sh
DATABASE_URL="$GROUP_DEMO_DATABASE_URL" \
REDIS_URL="$GROUP_DEMO_REDIS_URL" \
REDIS_KEY_PREFIX=group-demo-local-60220 \
MASTER_KEY_PATH=./master.key KMS_PROVIDER=file \
SERVER_NSEC=0000000000000000000000000000000000000000000000000000000000000001 \
PORT=60220 ALLOWED_TENANT_DOMAINS=localhost \
ENABLE_DEV_EMAIL_INBOX=true SENDGRID_API_KEY= \
ALLOWED_ORIGINS=http://localhost:60220 \
BASE_URL=http://localhost:60220 BUNKER_RELAYS=ws://127.0.0.1:60221 \
WEB_BUILD_DIR=web/build RUST_ENV=development NODE_ENV=development RUST_LOG=warn \
./target/debug/keycast
```

Once the server reports that its HTTP and signer listeners are running:

```sh
GROUP_DEMO_API_URL=http://localhost:60220 \
GROUP_DEMO_RELAY_URL=ws://127.0.0.1:60221 \
bun e2e/scripts/group-flow.mjs
```

The script refuses non-loopback API or relay URLs. It generates fresh synthetic accounts and client keys each run, retains credentials only in memory, and prints aggregate outcomes. It uses the development inbox exclusively to verify its own synthetic registrations. Stop the server and relay afterward; discard their synthetic state with the dedicated test services.

## Observed execution

Executed successfully on 2026-10-15 at 23:15–23:17 UTC with the normal debug server binary, the isolated migrated Postgres/Redis test services, file KMS, Bun 1.3.10, nostr-tools 2.23.0, ws 8.19.0, and nak 0.17.4. Dependency installation used the unchanged E2E lockfile.

| Assertion | Observed result |
| --- | --- |
| Three synthetic accounts registered and email verified through HTTP | Passed |
| Default hosted creation and retry preserve one group identity | Passed |
| Two invitations accepted; each admin receives a distinct device grant | Passed |
| Each admin connects, obtains the group public key, and signs while the other admins are offline | Passed through actual encrypted relay NIP-46 |
| Independent JavaScript BIP-340 verification | Passed for all four signed events |
| Relay acknowledges publication and a separate reader fetches the exact event | Passed for three admins and the replacement device |
| Removed admin's warm device | Explicit connect, get_public_key, and sign_event denials; fresh enrollment also refused |
| Replacement-device recovery | Fresh authorization and higher installation epoch; original group public key retained |
| Recovered admin's old device | Explicit connect, get_public_key, and sign_event denials |
| Non-loopback API and relay URL probes | Refused before making requests |
| Durable audit inspection after the run | Four sign_event rows, three enrollments, one recovery, one removal, and expected creation/invitation records |

The final credential-free script result was:

```json
{"result":"passed","synthetic":true,"independent_admins":3,"published_and_read_back":4,"removal_denials":3,"recovery_denials":3}
```

This demonstrates the hosted lifecycle and one-server relay path. FROST, backup-store disaster recovery, and multi-instance removal races have their own focused tests and are not claimed by this demonstration.
