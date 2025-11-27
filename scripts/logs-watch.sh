#!/bin/bash
# Watch Cloud Run logs with proper color rendering
# The logs already contain ANSI escape codes, just pass them through

watch -c -n 2 "gcloud logging read 'resource.type=cloud_run_revision AND resource.labels.service_name=keycast-unified' --limit=20 --project=openvine-co --format='value(textPayload)' 2>&1 | grep -v '^\$' | tail -20"
