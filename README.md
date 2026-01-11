# 📁 BFF (Backend-for-Frontend) Proxy

This Azure Function App acts as the BFF Layer for the application. Its primary responsibility is to act as a secure intermediary between the Frontend (Static Web App) and the downstream services (API Management & Auth0).

## 🛡️ Security Responsibilities

To keep the frontend "thin" and secure, this BFF handles the following:

- **Secret Masking**: Injects the `Ocp-Apim-Subscription-Key` into requests so the frontend never sees it.
- **Token Exchange**: Forwards Bearer tokens from the browser to the APIM.
- **Protocol Translation**: Handles the Auth0 Authorization Code Flow.
- **CORS Management**: Configured via Azure Functions portal settings.

## 🏗️ Architecture Flow

1. Frontend sends a request to `GET /api/proxy/{route}` (No APIM keys attached).
2. BFF validates the user's Bearer token (if provided).
3. BFF retrieves the APIM Key from environment variable or Azure Key Vault.
4. BFF forwards the request to APIM: `https://your-apim.azure-api.net/{route}`.
5. BFF returns the response to the Frontend.

## 📂 Project Structure

```
src/
├── functions/
│   ├── auth.ts          # Auth0 login/callback/logout handlers
│   ├── health.ts        # Health check endpoint
│   └── proxy.ts         # Main proxy endpoint
└── infra/
    ├── logging/
    │   └── logger.ts    # Application Insights logger
    ├── middleware/
    │   └── auth0-middleware.ts  # JWT validation
    └── services/
        └── apim-client.ts       # APIM forwarding client
```

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/proxy/{*route}` | GET, POST, PUT, PATCH, DELETE | Proxy to APIM |
| `/api/auth/login` | GET | Initiate Auth0 login |
| `/api/auth/callback` | GET | Auth0 callback handler |
| `/api/auth/logout` | GET | Initiate Auth0 logout |
| `/api/auth/me` | GET | Get current user info |

## ⚙️ Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `APIM_BASE_URL` | Base URL of the API Management gateway | Yes |
| `APIM_SUBSCRIPTION_KEY` | APIM subscription key (for local dev) | No* |
| `KEY_VAULT_URL` | Azure Key Vault URL | No* |
| `KEY_VAULT_SECRET_NAME` | Secret name for APIM key | No |
| `AUTH0_DOMAIN` | Auth0 tenant domain | Yes |
| `AUTH0_CLIENT_ID` | Auth0 application client ID | Yes |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | Yes |
| `AUTH0_AUDIENCE` | Auth0 API audience | Yes |
| `FRONTEND_URL` | Frontend URL for redirects | No |

*Either `APIM_SUBSCRIPTION_KEY` or `KEY_VAULT_URL` must be configured.

## 🚀 Getting Started

```bash
# Install dependencies
npm install

# Build
npm run build

# Start locally
npm start
```

## 🔐 Frontend Integration

Update your frontend to call the BFF instead of APIM directly:

```typescript
// Before (direct APIM call)
const API_URL = 'https://your-apim.azure-api.net';

// After (via BFF)
const API_URL = 'https://your-bff.azurewebsites.net/api/proxy';
```

The BFF will automatically inject the APIM subscription key into all requests.