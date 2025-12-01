#!/bin/bash
# Watch Cloud Run logs for keycast service

watch -n 2 "gcloud logging read 'resource.type=cloud_run_revision AND resource.labels.service_name=keycast' --limit=20 --project=openvine-co --format='value(jsonPayload.fields.message)' 2>&1 | grep -v '^\$'"
