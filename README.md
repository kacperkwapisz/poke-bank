# poke-bank

A [FastMCP](https://github.com/PrefectHQ/fastmcp) server that exposes [Enable Banking](https://enablebanking.com) (Open Banking) as MCP tools. Designed for easy self-hosting on a VPS with Docker.

Built as a companion to [poke-mail](https://github.com/kacperkwapisz/poke-mail), following the same structure and config conventions.

## Tools

| Tool | Description |
|---|---|
| `get_auth_url` | Start the authorization flow — returns a URL for the user to open and a `session_id` |
| `create_session` | Exchange the authorization code for a banking session (returns accounts) |
| `list_accounts` | List all bank accounts linked to a session |
| `get_transactions` | Get transactions for an account (optional date range filter) |
| `get_balances` | Get current balances for an account |

## Quick start

```bash
git clone https://github.com/kacperkwapisz/poke-bank
cd poke-bank
cp .env.example .env
# Edit .env — fill in MCP_API_KEY, Enable Banking credentials, SESSION_ENCRYPTION_KEY
docker compose up -d
```

The server listens on port `3000` (configurable via `HOST_PORT` in `.env`).

MCP endpoint: `http://your-vps:3000/mcp`

## Routes

| Path | Method | Description |
|---|---|---|
| `/mcp` | GET | Health check — returns `{"status": "ok"}` |
| `/mcp` | POST | MCP protocol endpoint |
| `/callback` | GET | Enable Banking redirect — auto-completes the authorization flow |

All other paths return 404.

## Configuration

All config is via environment variables (or `.env` file for Docker Compose).

| Variable | Required | Description |
|---|---|---|
| `MCP_API_KEY` | Yes | Bearer token for MCP clients |
| `ENABLE_BANKING_APP_ID` | Yes | Application UUID from the Enable Banking dashboard (JWT `kid`) |
| `ENABLE_BANKING_PRIVATE_KEY` | Yes | RSA private key PEM string or path to PEM file (signs API JWTs) |
| `ENABLE_BANKING_REDIRECT_URI` | Yes | Redirect URL registered with Enable Banking |
| `SESSION_ENCRYPTION_KEY` | Yes | 64 hex chars (32 bytes) for AES-256-GCM session encryption |
| `ENABLE_BANKING_BASE` | No | API base URL — defaults to `https://api.enablebanking.com` |
| `CONSENT_VALIDITY_DAYS` | No | Fallback consent validity in days when ASPSP lookup fails (default: 90). By default the maximum validity supported by the bank is used. |
| `DB_PATH` | No | SQLite path — defaults to `/data/sessions.db` |
| `RATE_LIMIT_GET_RPM` | No | GET rate limit per IP (default: 30) |
| `RATE_LIMIT_POST_RPM` | No | POST rate limit per IP (default: 120) |
| `POKE_WEBHOOK_URL` | No | Webhook URL to notify Poke when a bank account is connected |
| `POKE_API_KEY` | No | API key for Poke webhook authentication |
| `POKE_TUNNEL` | No | Set to `1` when using the Poke tunnel (disables MCP_API_KEY requirement) |
| `PORT` | No | Server port inside the container (default: 3000) |

### Generating keys

```bash
# MCP_API_KEY
openssl rand -hex 32

# SESSION_ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# RSA key pair for Enable Banking
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
# Upload public.pem to the Enable Banking dashboard, use private.pem as ENABLE_BANKING_PRIVATE_KEY
```

## Authentication

Enable Banking uses JWT-based authentication (not OAuth2 client credentials). Your application signs short-lived JWTs with the RSA private key registered in the Enable Banking dashboard. These JWTs are sent as Bearer tokens on every API request.

## Session store

Session metadata (authorization IDs, account lists) is stored in an encrypted SQLite database at `/data/sessions.db` inside the container. The `poke-bank-data` Docker volume persists this across restarts.

All session data is encrypted with AES-256-GCM using the `SESSION_ENCRYPTION_KEY`. The key never leaves your server.

## Authorization flow

1. Call `get_auth_url` with the bank name and country code
2. Open the returned `auth_url` in a browser and authorize
3. The bank redirects to `/callback` which auto-completes the session — no manual code copying needed
4. Use `list_accounts`, `get_transactions`, `get_balances` with the `session_id`

If `POKE_WEBHOOK_URL` and `POKE_API_KEY` are set, a webhook is sent to Poke when a bank account is successfully connected.

> **Fallback:** If the callback redirect doesn't work, you can also manually copy the `code` from the redirect URL and call `create_session` with the `code` and `session_id`.

## License

MIT
