#!/bin/bash
# ABOUTME: Set up Service Account for cross-project migration (KMS + DB access)
# ABOUTME: Uses Workload Identity - tests run as K8s Job in the cluster
# ABOUTME: Idempotent - safe to re-run. Creates SA and IAM bindings only if needed.
#
# Usage: ./scripts/migration-setup.sh [--test-only] [--skip-test]
#   --test-only: Skip setup, only run test job (assumes SA already exists)
#   --skip-test: Only do setup, don't run test job

set -euo pipefail

# Configuration
SA_NAME="keycast-migration"
SA_PROJECT="dv-platform-prod"
SA_EMAIL="${SA_NAME}@${SA_PROJECT}.iam.gserviceaccount.com"

SOURCE_PROJECT="openvine-co"
TARGET_PROJECT="dv-platform-prod"

# Database secrets (contain full DATABASE_URL with password)
SOURCE_DB_SECRET="keycast-database-url"
TARGET_DB_SECRET="keycast-db-url-production"

# Cloud SQL instance (source only - target uses in-cluster CNPG)
SOURCE_SQL_INSTANCE="openvine-co:us-central1:keycast-db-plus"

# KMS keys
SOURCE_KMS_KEY="projects/openvine-co/locations/global/keyRings/keycast-keys/cryptoKeys/master-key"
TARGET_KMS_KEY="projects/dv-platform-prod/locations/us-central1/keyRings/app-keys-production/cryptoKeys/keycast-master-key"

# K8s namespace for migration job
K8S_NAMESPACE="identity"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }
step() { echo -e "\n${GREEN}==>${NC} $1"; }

cleanup() {
    # Restore original gcloud config if we changed it
    if [ -n "${ORIGINAL_CONFIG:-}" ]; then
        gcloud config configurations activate "$ORIGINAL_CONFIG" &>/dev/null || true
    fi
}
trap cleanup EXIT

# Parse arguments
TEST_ONLY=false
SKIP_TEST=false
for arg in "$@"; do
    case $arg in
        --test-only) TEST_ONLY=true ;;
        --skip-test) SKIP_TEST=true ;;
    esac
done

echo "========================================"
echo "Migration Setup (KMS + DB Access)"
echo "========================================"
echo ""
echo "Service Account: $SA_EMAIL"
echo "Source Project:  $SOURCE_PROJECT (KMS decrypt, DB read)"
echo "Target Project:  $TARGET_PROJECT (KMS encrypt/decrypt, DB write)"
echo ""

# Save current config to restore later
ORIGINAL_CONFIG=$(gcloud config configurations list --filter="is_active=true" --format="value(name)" 2>/dev/null || echo "")

if [ "$TEST_ONLY" = false ]; then
    # ========================================
    # STEP 1: Create GCP Service Account (if needed)
    # ========================================
    step "Checking GCP Service Account..."

    # Switch to target project for SA creation
    gcloud config configurations activate divine &>/dev/null || {
        error "Could not activate 'divine' gcloud config. Please run: gcloud config configurations activate divine && gcloud auth login"
        exit 1
    }

    if gcloud iam service-accounts describe "$SA_EMAIL" --project="$SA_PROJECT" &>/dev/null; then
        info "GCP Service Account already exists: $SA_EMAIL"
    else
        warn "Creating GCP Service Account: $SA_EMAIL"
        gcloud iam service-accounts create "$SA_NAME" \
            --display-name="Keycast Migration (cross-project)" \
            --description="Used for migrating data between openvine-co and dv-platform-prod" \
            --project="$SA_PROJECT"
        info "GCP Service Account created"
    fi

    # ========================================
    # STEP 2: Grant KMS access in TARGET project
    # ========================================
    step "Setting up KMS access in TARGET project (${TARGET_PROJECT})..."

    warn "Adding KMS IAM binding in $TARGET_PROJECT..."
    gcloud projects add-iam-policy-binding "$TARGET_PROJECT" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
        --quiet >/dev/null
    info "KMS IAM binding configured in $TARGET_PROJECT"

    # ========================================
    # STEP 3: Grant KMS access in SOURCE project (cross-project)
    # ========================================
    step "Setting up KMS access in SOURCE project (${SOURCE_PROJECT})..."

    gcloud config configurations activate default &>/dev/null || {
        error "Could not activate 'default' gcloud config"
        exit 1
    }

    warn "Adding KMS IAM binding in $SOURCE_PROJECT (cross-project access)..."
    gcloud projects add-iam-policy-binding "$SOURCE_PROJECT" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="roles/cloudkms.cryptoKeyDecrypter" \
        --quiet >/dev/null
    info "KMS IAM binding configured in $SOURCE_PROJECT"

    # ========================================
    # STEP 4: Grant Cloud SQL access (source only - target uses CNPG)
    # ========================================
    step "Setting up Cloud SQL access for SOURCE..."

    warn "Adding Cloud SQL IAM binding in $SOURCE_PROJECT..."
    gcloud projects add-iam-policy-binding "$SOURCE_PROJECT" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="roles/cloudsql.client" \
        --quiet >/dev/null
    info "Cloud SQL IAM binding configured in $SOURCE_PROJECT"

    # ========================================
    # STEP 5: Grant Secret Manager access for DATABASE_URL secrets
    # ========================================
    step "Setting up Secret Manager access for DATABASE_URL..."

    # Source project - DATABASE_URL secret
    warn "Granting access to $SOURCE_DB_SECRET in $SOURCE_PROJECT..."
    gcloud secrets add-iam-policy-binding "$SOURCE_DB_SECRET" \
        --project="$SOURCE_PROJECT" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet >/dev/null
    info "Secret access configured for $SOURCE_DB_SECRET"

    # Target project - DATABASE_URL secret
    gcloud config configurations activate divine &>/dev/null
    warn "Granting access to $TARGET_DB_SECRET in $TARGET_PROJECT..."
    gcloud secrets add-iam-policy-binding "$TARGET_DB_SECRET" \
        --project="$TARGET_PROJECT" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet >/dev/null
    info "Secret access configured for $TARGET_DB_SECRET"

    # ========================================
    # STEP 6: Set up Workload Identity binding
    # ========================================
    step "Setting up Workload Identity binding..."

    # Allow K8s SA to impersonate GCP SA
    gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
        --project="$SA_PROJECT" \
        --role="roles/iam.workloadIdentityUser" \
        --member="serviceAccount:${SA_PROJECT}.svc.id.goog[${K8S_NAMESPACE}/${SA_NAME}]" \
        --quiet >/dev/null
    info "Workload Identity binding configured"

    # ========================================
    # STEP 7: Create K8s ServiceAccount
    # ========================================
    step "Creating K8s ServiceAccount..."

    # Get cluster credentials
    gcloud container clusters get-credentials gke-production --region=us-central1 --project="$SA_PROJECT" 2>/dev/null

    # Create K8s ServiceAccount with Workload Identity annotation
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${SA_NAME}
  namespace: ${K8S_NAMESPACE}
  annotations:
    iam.gke.io/gcp-service-account: ${SA_EMAIL}
EOF
    info "K8s ServiceAccount created/updated"

    echo ""
    info "Setup complete! IAM changes may take up to 60 seconds to propagate."
    echo ""
fi

if [ "$SKIP_TEST" = true ]; then
    echo "Skipping test (--skip-test specified)"
    exit 0
fi

# ========================================
# STEP 8: Run test Job in cluster
# ========================================
step "Running migration access test as K8s Job..."

# Make sure we have cluster credentials
gcloud config configurations activate divine &>/dev/null
gcloud container clusters get-credentials gke-production --region=us-central1 --project="$SA_PROJECT" 2>/dev/null

# Delete old test job if exists
kubectl delete job migration-access-test -n "$K8S_NAMESPACE" 2>/dev/null || true

# Create and run test job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: migration-access-test
  namespace: ${K8S_NAMESPACE}
spec:
  ttlSecondsAfterFinished: 300
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: ${SA_NAME}
      restartPolicy: Never
      containers:
      - name: test
        image: google/cloud-sdk:slim
        command:
        - /bin/bash
        - -c
        - |
          set -e
          echo "========================================"
          echo "Migration Access Test"
          echo "========================================"
          echo ""

          # Test 1: KMS encrypt/decrypt on TARGET
          echo "=== TEST 1: KMS Target (encrypt/decrypt) ==="
          TEST_DATA="migration-test-\$(date +%s)"
          echo -n "\$TEST_DATA" > /tmp/plaintext.txt

          if gcloud kms encrypt \
              --location=us-central1 \
              --keyring=app-keys-production \
              --key=keycast-master-key \
              --plaintext-file=/tmp/plaintext.txt \
              --ciphertext-file=/tmp/ciphertext.bin \
              --project=${TARGET_PROJECT} 2>&1; then
              echo "✓ Target KMS encrypt: OK"
          else
              echo "✗ Target KMS encrypt: FAILED"
              exit 1
          fi

          if gcloud kms decrypt \
              --location=us-central1 \
              --keyring=app-keys-production \
              --key=keycast-master-key \
              --ciphertext-file=/tmp/ciphertext.bin \
              --plaintext-file=/tmp/decrypted.txt \
              --project=${TARGET_PROJECT} 2>&1; then
              if [ "\$(cat /tmp/decrypted.txt)" = "\$TEST_DATA" ]; then
                  echo "✓ Target KMS decrypt: OK (verified)"
              else
                  echo "✗ Target KMS decrypt: data mismatch"
                  exit 1
              fi
          else
              echo "✗ Target KMS decrypt: FAILED"
              exit 1
          fi
          echo ""

          # Test 2: KMS decrypt on SOURCE
          echo "=== TEST 2: KMS Source (decrypt only) ==="
          # We can only test that we have permission, not actual decrypt (different key)
          if gcloud kms keys describe master-key \
              --location=global \
              --keyring=keycast-keys \
              --project=${SOURCE_PROJECT} 2>&1 | grep -q "name:"; then
              echo "✓ Source KMS access: OK (key accessible)"
          else
              echo "✗ Source KMS access: FAILED"
              exit 1
          fi
          echo ""

          # Test 3: Secret Manager - Source DATABASE_URL
          echo "=== TEST 3: Secret Manager (DATABASE_URLs) ==="
          if gcloud secrets versions access latest \
              --secret=${SOURCE_DB_SECRET} \
              --project=${SOURCE_PROJECT} >/dev/null 2>&1; then
              echo "✓ Source DATABASE_URL secret: accessible"
          else
              echo "✗ Source DATABASE_URL secret: FAILED"
              exit 1
          fi

          if gcloud secrets versions access latest \
              --secret=${TARGET_DB_SECRET} \
              --project=${TARGET_PROJECT} >/dev/null 2>&1; then
              echo "✓ Target DATABASE_URL secret: accessible"
          else
              echo "✗ Target DATABASE_URL secret: FAILED"
              exit 1
          fi
          echo ""

          # Test 4: Database connectivity (basic - just test we can parse URL)
          echo "=== TEST 4: Database URL validation ==="
          SOURCE_URL=\$(gcloud secrets versions access latest --secret=${SOURCE_DB_SECRET} --project=${SOURCE_PROJECT})
          TARGET_URL=\$(gcloud secrets versions access latest --secret=${TARGET_DB_SECRET} --project=${TARGET_PROJECT})

          if echo "\$SOURCE_URL" | grep -q "postgres://"; then
              echo "✓ Source DATABASE_URL: valid postgres URL"
          else
              echo "✗ Source DATABASE_URL: invalid format"
              exit 1
          fi

          if echo "\$TARGET_URL" | grep -q "postgres://"; then
              echo "✓ Target DATABASE_URL: valid postgres URL"
          else
              echo "✗ Target DATABASE_URL: invalid format"
              exit 1
          fi
          echo ""

          echo "========================================"
          echo "All tests passed!"
          echo "========================================"
EOF

echo ""
info "Job created. Waiting for completion..."

# Wait for job to complete
if kubectl wait --for=condition=complete job/migration-access-test -n "$K8S_NAMESPACE" --timeout=120s 2>/dev/null; then
    echo ""
    info "Job completed successfully!"
    echo ""
    echo "=== Job Logs ==="
    kubectl logs job/migration-access-test -n "$K8S_NAMESPACE"
else
    echo ""
    error "Job failed or timed out"
    echo ""
    echo "=== Job Logs ==="
    kubectl logs job/migration-access-test -n "$K8S_NAMESPACE" 2>/dev/null || echo "No logs available"
    exit 1
fi

# Cleanup
kubectl delete job migration-access-test -n "$K8S_NAMESPACE" 2>/dev/null || true

echo ""
echo "========================================"
echo "Migration SA is ready!"
echo ""
echo "To use in a migration job:"
echo "  serviceAccountName: ${SA_NAME}"
echo "  namespace: ${K8S_NAMESPACE}"
echo "========================================"
