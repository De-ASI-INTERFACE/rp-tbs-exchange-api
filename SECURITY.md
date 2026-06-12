# Security Policy — rp-tbs-exchange-api

## Reporting Vulnerabilities

Email: **security@deasi.ai** | Response SLA: 48 hours | Patch SLA: 7 days (critical)

Do NOT open public GitHub issues for security vulnerabilities.

## Exchange API Specific Standards

### Authentication
- JWT access tokens: 15-minute expiry maximum in production
- Refresh tokens: rotated on every use, invalidated on logout
- All `/api/v1/orders` and `/api/v1/account` endpoints require Bearer JWT
- KYC status verified on every order placement, not just login

### WebSocket Security
- Connections authenticated within 10 seconds of upgrade or forcibly closed
- Per-connection rate limiting: 100 messages/minute
- Message size limit: 64 KB
- Reconnect tokens are single-use and 5-minute TTL

### Order Management
- Order amounts validated against user's verified balance before acceptance
- Slippage tolerance capped at configurable MAX_SLIPPAGE_BPS
- Duplicate order detection via idempotency keys
- All order mutations logged to immutable audit trail

### Exchange Integrations (Coinbase / Binance)
- API keys stored exclusively in environment variables
- HMAC signatures verified on all incoming webhooks
- Response payloads schema-validated before order state mutation
