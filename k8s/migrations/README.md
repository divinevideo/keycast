# One-off Migration Jobs

Kubernetes Job manifests for one-time data migrations. These are applied manually via `kubectl apply -f` and are not part of the continuous deployment pipeline.

Each manifest is environment-specific and kept here as a historical record of what was run.

## Vine User Migration

Migrates all users from the original openvine-co Cloud SQL database to the target environment's CloudNativePG cluster. Decrypts private keys with the source KMS (openvine-co) and re-encrypts with the target environment's KMS.

- `migrate-vine-users-poc.yaml` - POC environment
- `migrate-vine-users-production.yaml` - Production environment

Both manifests default to `DRY_RUN=true`. Set to `false` when ready to run for real.

The migration binary is idempotent: re-running skips users that already exist in the target database.
