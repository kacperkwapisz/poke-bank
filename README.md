# poke-bank

A [FastMCP](https://github.com/PrefectHQ/fastmcp) server that exposes [Enable Banking](https://enablebanking.com) (Open Banking) as MCP tools. Designed for easy self-hosting on a VPS with Docker.

Built as a companion to [poke-mail](https://github.com/kacperkwapisz/poke-mail), following the same structure and config conventions.

## Tools

| Tool | Description |
|---|---|
| `get_auth_url` | Start the OAuth2 flow — returns an authorization URL and a `session_id` |
| `exchange_code` | Exchange the authorization code for access + refresh tokens |
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

## Configuration

All config is via environment variables (or `.env` file for Docker Compose).

| Variable | Required | Description |
|---|---|---|
| `MCP_API_KEY` | Yes | Bearer token for MCP clients |
| `ENABLE_BANKING_CLIENT_ID` | Yes | Enable Banking OAuth2 client ID |
| `ENABLE_BANKING_CLIENT_SECRET` | Yes | Enable Banking OAuth2 client secret |
| `ENABLE_BANKING_REDIRECT_URI` | Yes | OAuth2 redirect URI registered with Enable Banking |
| `SESSION_ENCRYPTION_KEY` | Yes | 64 hex chars (32 bytes) for AES-256-GCM session encryption |
| `ENABLE_BANKING_BASE` | No | API base URL — defaults to `https://api.enablebanking.com` |
| `DB_PATH` | No | SQLite path — defaults to `/data/sessions.db` |
| `RATE_LIMIT_GET_RPM` | No | GET rate limit per IP (default: 30) |
| `RATE_LIMIT_POST_RPM` | No | POST rate limit per IP (default: 120) |
| `POKE_TUNNEL` | No | Set to `1` when using the Poke tunnel (disables MCP_API_KEY requirement) |
| `PORT` | No | Server port inside the container (default: 3000) |

### Generating keys

```bash
# MCP_API_KEY
openssl rand -hex 32

# SESSION_ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_hex(32))"
```

## Session store

Sessions (access tokens, refresh tokens) are stored in an encrypted SQLite database at `/data/sessions.db` inside the container. The `poke-bank-data` Docker volume persists this across restarts.

All session data is encrypted with AES-256-GCM using the `SESSION_ENCRYPTION_KEY`. The key never leaves your server.

## OAuth2 flow

1. Call `get_auth_url` with the bank name and country code
2. Open the returned `auth_url` in a browser and authorize
3. After the redirect, copy the `code` from the URL
4. Call `exchange_code` with the `code` and `session_id`
5. Use `list_accounts`, `get_transactions`, `get_balances` with the `session_id`

## License

MIT
