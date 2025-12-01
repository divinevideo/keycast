# Keycast Production Monitoring Guide

## Overview
Keycast uses Google Cloud's native monitoring and logging infrastructure for production observability.

## Logging

### Structured JSON Logs
Production automatically uses JSON-formatted logs compatible with Cloud Logging:
- **Environment**: `NODE_ENV=production` triggers JSON logging
- **Format**: Structured JSON with targets, spans, and timestamps
- **Development**: Human-readable logs for local development

### Viewing Logs
```bash
# View recent logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=keycast" \
  --project=openvine-co \
  --limit=50 \
  --format='value(jsonPayload.fields.message)'

# View error logs only
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=keycast AND severity>=ERROR" \
  --project=openvine-co \
  --limit=50

# Tail logs in real-time
gcloud alpha logging tail "resource.type=cloud_run_revision AND resource.labels.service_name=keycast" \
  --project=openvine-co
```

### Log Levels
- `ERROR`: Application errors, failed requests
- `WARN`: Warnings, recoverable issues
- `INFO`: Normal operations, API requests (default)
- `DEBUG`: Detailed debugging information

## Error Monitoring

### Cloud Error Reporting
Cloud Error Reporting automatically groups similar errors and tracks:
- Error frequency
- Affected users
- Stack traces
- First/last seen timestamps

**View errors:**
```bash
# In Google Cloud Console
https://console.cloud.google.com/errors?project=openvine-co

# Or via CLI
gcloud error-reporting events list --project=openvine-co
```

### Key Metrics to Monitor

1. **Error Rate**
   - Track 4xx and 5xx response codes
   - Set alert threshold: >5% error rate

2. **Response Time**
   - P50, P95, P99 latencies
   - Set alert threshold: P95 > 1000ms

3. **Request Volume**
   - Requests per second
   - Unusual spikes or drops

4. **CORS Failures**
   - Track OPTIONS requests failing
   - Monitor blocked origins

## Health Checks

### API Health Endpoint
```bash
# Production
curl https://login.divine.video/health

# Local
curl http://localhost:3000/health
```

### Integration Tests
Run comprehensive tests against production:
```bash
API_URL=https://login.divine.video FRONTEND_URL=https://login.divine.video \
  ./tests/integration/test-api.sh
```

## Setting Up Alerts

### Recommended Alerts

1. **High Error Rate**
```bash
gcloud alpha monitoring policies create \
  --notification-channels=YOUR_CHANNEL \
  --display-name="Keycast High Error Rate" \
  --condition-display-name="Error rate >5%" \
  --condition-threshold-value=0.05 \
  --condition-threshold-duration=300s \
  --project=openvine-co
```

2. **Service Unavailable**
```bash
gcloud alpha monitoring uptime create \
  --display-name="Keycast API Health" \
  --resource-type=uptime-url \
  --monitored-resource=https://login.divine.video/health \
  --period=60s \
  --project=openvine-co
```

3. **High Latency**
   - Monitor response_latency metric
   - Alert when P95 > 1000ms for 5 minutes

## Dashboards

### Cloud Console Dashboards
1. **Service Dashboard**: https://console.cloud.google.com/run/detail/us-central1/keycast
2. **Logs Explorer**: https://console.cloud.google.com/logs/query
3. **Error Reporting**: https://console.cloud.google.com/errors
4. **Metrics**: https://console.cloud.google.com/monitoring

### Key Metrics to Dashboard
- Request count (by status code)
- Request latency (P50, P95, P99)
- Container CPU utilization
- Container memory utilization
- Error rate over time
- CORS preflight success rate

## Troubleshooting

### Common Issues

**High Error Rate**
1. Check logs for error patterns
2. Verify environment variables
3. Check database connectivity
4. Review recent deployments

**CORS Failures**
1. Verify CORS_ALLOWED_ORIGIN is set correctly
2. Check Cloud Run service configuration
3. Review API logs for blocked origins

**High Latency**
1. Check database query performance
2. Review container resources (CPU/memory)
3. Check for N+1 queries
4. Monitor external API calls

**Deployment Failures**
1. Review Cloud Build logs
2. Check smoke tests in cloudbuild.yaml
3. Verify environment secrets are accessible
4. Test locally with `./test-local.sh` first

## Log Retention

- **Cloud Logging**: 30 days by default
- **Error Reporting**: 90 days
- **Metrics**: 6 weeks (aggregated data retained longer)

To increase retention, configure log sinks to Cloud Storage or BigQuery.

## Performance Monitoring

### Cloud Trace
Cloud Trace automatically captures request traces:
```bash
# View traces
https://console.cloud.google.com/traces/list?project=openvine-co
```

### Request Tracing
All requests include:
- Request ID (from tower-http middleware)
- Span information (from tracing-subscriber)
- Timing data for each operation

## Security Monitoring

### Key Security Metrics
1. **Failed authentication attempts**
2. **Unusual request patterns**
3. **Geographic anomalies**
4. **Rate limit violations** (once implemented)

### Audit Logs
Cloud Audit Logs track:
- Service configuration changes
- IAM permission changes
- Secret access
- Deployment events

```bash
# View audit logs
gcloud logging read "logName:cloudaudit.googleapis.com" \
  --project=openvine-co \
  --limit=50
```

## Next Steps

### Recommended Improvements
1. **Set up alerting policies** for high error rate and latency
2. **Create custom dashboard** with key metrics
3. **Configure log sinks** for long-term retention
4. **Add request ID tracking** to all responses
5. **Implement rate limiting** and monitor violations
6. **Set up Slack/PagerDuty** notifications for critical alerts
