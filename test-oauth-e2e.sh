#!/bin/bash
set -e

API_URL="https://login.divine.video"
EMAIL="test-$(date +%s)@example.com"
PASSWORD="testpassword123"

echo "=========================================="
echo "🧪 End-to-End OAuth + NIP-46 Test"
echo "=========================================="
echo "API: $API_URL"
echo "Email: $EMAIL"
echo ""

# Step 1: Register
echo "📝 Step 1: Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

JWT_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.token')

if [ "$JWT_TOKEN" = "null" ] || [ -z "$JWT_TOKEN" ]; then
  echo "❌ Registration failed!"
  echo "$REGISTER_RESPONSE" | jq .
  exit 1
fi

echo "✅ Registered successfully"
echo "JWT Token: ${JWT_TOKEN:0:20}..."
echo ""

# Step 2: OAuth Approve
echo "🔐 Step 2: Getting OAuth authorization..."
APPROVE_RESPONSE=$(curl -s -X POST "$API_URL/api/oauth/authorize" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "client_id": "test-e2e-client",
    "redirect_uri": "http://localhost:8000/callback",
    "scope": "sign_event",
    "approved": true
  }')

AUTH_CODE=$(echo "$APPROVE_RESPONSE" | jq -r '.code')

if [ "$AUTH_CODE" = "null" ] || [ -z "$AUTH_CODE" ]; then
  echo "❌ OAuth authorization failed!"
  echo "$APPROVE_RESPONSE" | jq .
  exit 1
fi

echo "✅ Got authorization code: ${AUTH_CODE:0:20}..."
echo ""

# Step 3: Exchange code for bunker URL
echo "🔑 Step 3: Exchanging code for bunker URL..."
TOKEN_RESPONSE=$(curl -s -X POST "$API_URL/api/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"code\":\"$AUTH_CODE\",
    \"client_id\":\"test-e2e-client\",
    \"redirect_uri\":\"http://localhost:8000/callback\"
  }")

BUNKER_URL=$(echo "$TOKEN_RESPONSE" | jq -r '.bunker_url')

if [ "$BUNKER_URL" = "null" ] || [ -z "$BUNKER_URL" ]; then
  echo "❌ Token exchange failed!"
  echo "$TOKEN_RESPONSE" | jq .
  exit 1
fi

echo "✅ Got bunker URL!"
echo "$BUNKER_URL"
echo ""

# Parse bunker URL
BUNKER_PUBKEY=$(echo "$BUNKER_URL" | sed -n 's/^bunker:\/\/\([0-9a-f]*\).*/\1/p')
RELAY_URL=$(echo "$BUNKER_URL" | sed -n 's/.*relay=\([^&]*\).*/\1/p')
SECRET=$(echo "$BUNKER_URL" | sed -n 's/.*secret=\([^&]*\).*/\1/p')

echo "📊 Parsed bunker details:"
echo "  Bunker Pubkey: $BUNKER_PUBKEY"
echo "  Relay: $RELAY_URL"
echo "  Secret: ${SECRET:0:10}..."
echo ""

# Step 4: Wait for signer to reload
echo "⏳ Step 4: Waiting 5 seconds for signer to detect and load the new authorization..."
sleep 5
echo ""

# Step 5: Use nostr-tools to test NIP-46 connection
echo "🔌 Step 5: Testing NIP-46 connection via relay..."
echo "(This would require Node.js and nostr-tools to send encrypted NIP-46 requests)"
echo ""

echo "=========================================="
echo "✅ OAuth Flow Complete!"
echo "=========================================="
echo ""
echo "The OAuth + bunker URL generation is working!"
echo ""
echo "Next: Check the signer logs to verify it loaded the authorization:"
echo "  gcloud logging read 'resource.labels.service_name=\"keycast-oauth\" AND textPayload=~\"Added NEW OAuth authorization\"' --project=openvine-co --limit=5 --format=\"value(textPayload)\""
echo ""
