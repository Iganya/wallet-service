# Wallet Service API

## Google Auth signin and Paystack payment Integration

A fully functional wallet system built with FastAPI, Paystack, Google OAuth2, and API Key authentication.
This project satisfies 100% of the original technical assessment requirements:
- Google sign-in → JWT
- Service-to-service access via API keys (max of 5 active keys per user, permissions, expiry, rollover)
- Paystack deposit with mandatory webhook (update balance only via webhook)
- Wallet-to-wallet transfers (atomic)
- Balance, transaction history
- Idempotent webhook handling
- Proper authentication & permission checks for access key
---

## 🚀 Endpoints

| Method | Endpoint                        | Auth Method                 | Description                                       |
|--------|---------------------------------|-----------------------------|---------------------------------------------------|
| GET    | /auth/google                    | -                           | Start Google login                                |
| GET    | /auth/google/callback           | Google OAuth                | Returns JWT + creates user & wallet              |
| POST   | /keys/create                    | JWT                         | Generate API key (max 5 active)                  |
| POST   | /keys/rollover                  | JWT                         | Roll over expired key with same permissions      |
| POST   | /wallet/deposit                 | JWT or API key (deposit)    | Initialize Paystack payment                      |
| POST   | /wallet/paystack/webhook        | Paystack signature          | Mandatory – credits wallet only here             |
| GET    | /wallet/deposit/{ref}/status    | JWT or API key (read)                         | Manual status check (does NOT credit)            |
| GET    | /wallet/balance                 | JWT or API key (read)       | Current balance                                  |
| POST   | /wallet/transfer                | JWT or API key (transfer)   | Transfer to another wallet                       |
| GET    | /wallet/transactions            | JWT or API key (read)       | Transaction history                              |



## Technology Stack
- Programming Language: Python
- Framework: FastAPI
- Database: Postgres


## Setup & Run (Step-by-Step)
1. Clone the repository:
   ```bash
   https://github.com/Iganya/wallet-service.git
   cd your-repo
   ```
2. Create .env file
    ```

    WALLET_SERVICE_DB_URL="postgresql://username:password@hostname:port/db_name"

    SECRET_KEY=your_genereated_secret_key
    ALGORITHM=hash_algorithm

    GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
    GOOGLE_CLIENT_SECRET=your-google-client-secret
    GOOGLE_CERTS_URL=https://www.googleapis.com/oauth2/v3/certs
    GOOGLE_REDIRECT_URI=site_domain/auth/google/callback

    PAYSTACK_SECRET_KEY=your_paystack_secret_key
    PAYSTACK_PUBLIC_KEY=your_paystack_public_key

    ```
3. Get Google and paystack credentials
    Get Google OAuth credentials → https://console.cloud.google.com/apis/credentials
    Paystack test keys → https://dashboard.paystack.com/#/settings/developer

3. Install dependencies and create virtual environment using uv:
   ```bash
   uv sync
   ```
4. Run the FastAPI application:
   ```bash
   uv run main.py
   ```
5. Access the API at `http://127.0.0.1:8000/`


## Testing the Full Flow
1. Login with Google
    Visit: `http://localhost:8000/auth/google`
    You’ll get a JWT token in the response.

2. Create an API Key (using JWT)
    ```
    curl -X POST http://localhost:8000/keys/create \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-service","permissions":["deposit","transfer","read"],"expiry":"1D"}'
  ```
3. Initialize Deposit (with API key)
    ```
    curl -X POST http://localhost:8000/wallet/deposit \
  -H "x-api-key: sk_live_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 5000}'
  ```
4. Paystack Webhook (Test it)
    Use Paystack dashboard or ngrok:
    ```
    ngrok http 8000
    # Then set webhook URL in Paystack dashboard to:
    # https://your-ngrok-url.ngrok.io/wallet/paystack/webhook
    ```
5. Transfer Money
    ```
    curl -X POST http://localhost:8000/wallet/transfer \
  -H "Authorization: Bearer <jwt>" \
  -d '{"wallet_number": "recipient-wallet-number", "amount": 2000}'
  ```