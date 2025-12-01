#!/bin/bash
# View Cloud Run logs for keycast service

set -e

PROJECT="openvine-co"
SERVICE="keycast"

echo "Viewing recent logs for $SERVICE..."
echo "To stream logs continuously, use: pnpm run logs:watch"
echo ""

gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE" \
  --limit=50 \
  --project=$PROJECT \
  --format="value(timestamp,jsonPayload.level,jsonPayload.fields.message)"
