#!/bin/bash
# View Cloud Run logs for keycast-unified service

set -e

PROJECT="openvine-co"
SERVICE="keycast-unified"

echo "📋 Viewing recent logs for $SERVICE on GCP..."
echo "Open in browser: https://console.cloud.google.com/run/detail/us-central1/$SERVICE/logs?project=$PROJECT"
echo ""

# Show recent logs (last 50), strip ANSI color codes
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE" \
  --limit=50 \
  --project=$PROJECT \
  --format="value(timestamp,severity,textPayload)" \
  | sed 's/\x1b\[[0-9;]*m//g'
