# Keycast OAuth Test Client

## Overview
`test-oauth-client.html` is a standalone test client for testing user registration and NIP-46 bunker URL retrieval.

## Status: ⚠️ INCOMPLETE
The test client is ready, but the required API endpoints are **not yet implemented** in the Keycast API.

## Required API Endpoints

The test client requires these endpoints to be implemented:

### 1. `POST /api/auth/register`
**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "user_id": "uuid-here",
  "email": "user@example.com"
}
```

### 2. `POST /api/auth/login`
**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "token": "jwt-token-here",
  "pubkey": "nostr-pubkey-hex"
}
```

### 3. `GET /api/user/bunker`
**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "bunker_url": "bunker://<pubkey>?relay=wss://relay.example.com&secret=<secret>"
}
```

## Usage (Once Endpoints Implemented)

### 1. Start Local Services
```bash
./test-local.sh
```

### 2. Open Test Client
Open `examples/test-oauth-client.html` in a web browser.

### 3. Test Flow
1. **Create User**: Enter email and password, click "Create User"
2. **Login**: Use the same credentials, click "Login"
3. **Get Bunker URL**: Click "Get Bunker URL" to retrieve your NIP-46 connection string

### 4. Test Against Production
Change the API URL field to `https://login.divine.video`

## Current API Status
As of now, the Keycast API only implements team-related endpoints:
- `/teams` (GET, POST)
- `/teams/:id` (GET, PUT, DELETE)
- `/teams/:id/users` (POST, DELETE)
- `/teams/:id/keys` (POST, GET, DELETE)
- `/teams/:id/keys/:pubkey/authorizations` (POST)
- `/teams/:id/policies` (POST)

**Next Steps:**
1. Implement personal authentication endpoints (`/api/auth/*`)
2. Implement user bunker URL endpoint (`/api/user/bunker`)
3. Test with this client
4. Update this README once endpoints are working

## Features
- ✅ Clean, dark-themed UI
- ✅ Real-time logging with timestamps
- ✅ Configurable API URL (local/production)
- ✅ Error handling and user feedback
- ✅ Auto-fill login after registration
- ✅ Copy-friendly bunker URL display
- ⚠️ Waiting on backend API endpoints
