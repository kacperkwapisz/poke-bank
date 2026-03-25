# poke-bank

An MCP server that exposes [Enable Banking](https://enablebanking.com) (EU/Nordic) and [Teller](https://teller.io) (US) as MCP tools for [Poke](https://poke.com). Provides AI agents with tools to connect bank accounts, list accounts, fetch transactions, and check balances.

## Features

- **Dual provider support**: Enable Banking for EU/Nordic banks, Teller for US banks
- **5 MCP tools**: authorize bank connections, list accounts, get transactions, get balances, create sessions
- **Automatic callback**: Bank redirects back to `/callback` which auto-completes the session — no manual code copying
- **Teller Connect widget**: Embedded JS widget at `/connect/teller` for US bank enrollment (100 free enrollments)
- **Encrypted session store**: AES-256-GCM encrypted SQLite database for session metadata
- **Bearer token auth**: Secure the server with `MCP_API_KEY` so only you can use it
- **Poke webhook**: Automatically notifies Poke when a bank account is connected

## Quick Start

**Prerequisites:** Python 3.10+ and Node.js 18+ (which includes `npx` and `npm`).

```bash
git clone https://github.com/kacperkwapisz/poke-bank.git
cd poke-bank
```

If you haven't logged into Poke yet, do that first — `start.sh` will pick up your token automatically:

```bash
npx poke login
```

Then just run:

```bash
./start.sh
```

On the **first run**, `start.sh` automatically handles the full setup:
1. Creates a Python virtualenv and installs dependencies
2. Copies `.env.example` → `.env`
3. Reads your Poke API key from `poke login` credentials and injects it into `.env`
4. Generates a random `MCP_API_KEY` and `SESSION_ENCRYPTION_KEY` and saves them to `.env`
5. Prompts you for your `ENABLE_BANKING_APP_ID` (or you can set it manually in `.env` later)
6. Immediately starts the server and tunnel

After the first run, open `.env` and fill in your provider credentials — Enable Banking (`ENABLE_BANKING_APP_ID`, `ENABLE_BANKING_PRIVATE_KEY`, `ENABLE_BANKING_REDIRECT_URI`) for EU/Nordic banks and/or Teller (`TELLER_APP_ID`, `TELLER_CERT`, `TELLER_KEY`) for US banks — then run `./start.sh` again.

On **subsequent runs**, `start.sh` skips setup and goes straight to starting the server and tunnel.

### AI coding agent setup

Copy this prompt into your AI coding agent (Claude Code, Cursor, etc.):

```text
Set up poke-bank (https://github.com/kacperkwapisz/poke-bank) for me — clone the repo, run 'npx poke login' so I can authenticate with Poke (wait for me to confirm), then run './start.sh' which will automatically wire up my Poke API key, generate an MCP_API_KEY and SESSION_ENCRYPTION_KEY, set up the virtualenv, and start the server and tunnel. Before configuring bank providers, ask me: "Do you want to connect US banks, EU/Nordic banks, or both?" Then only set up what I choose. For EU/Nordic banks (Enable Banking): guide me to https://enablebanking.com to create an application, generate an RSA key pair (openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -pubout -out public.pem), upload the public key to the dashboard, copy the Application ID into ENABLE_BANKING_APP_ID, and set ENABLE_BANKING_REDIRECT_URI to https://<my-domain>/callback. For US banks (Teller): guide me to https://teller.io to create an application, copy the Application ID into TELLER_APP_ID, and download the mTLS certificate (teller.zip) — extract certificate.pem and private_key.pem and set TELLER_CERT and TELLER_KEY to their paths (not needed for sandbox mode). Do NOT type passwords or secrets, tell me to enter those myself and confirm when done; if the server fails due to missing credentials, have me update .env and run './start.sh' again.
```

## Enable Banking Setup

To use poke-bank, you need credentials from [Enable Banking](https://enablebanking.com):

1. **Create an account** at [enablebanking.com](https://enablebanking.com) and create a new application
2. **Generate an RSA key pair** for JWT signing:
   ```bash
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout -out public.pem
   ```
3. **Upload `public.pem`** to the Enable Banking dashboard under your application
4. **Copy the Application ID** (a UUID) — this is your `ENABLE_BANKING_APP_ID`
5. **Set the redirect URI** in the dashboard to `https://<your-domain>/callback` — this must match `ENABLE_BANKING_REDIRECT_URI` in `.env`
6. **Add credentials to `.env`**:
   ```bash
   ENABLE_BANKING_APP_ID=<your-application-uuid>
   ENABLE_BANKING_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
   ENABLE_BANKING_REDIRECT_URI=https://your-domain.com/callback
   ```

> **Note:** You can also point `ENABLE_BANKING_PRIVATE_KEY` to the PEM file path instead of inlining the key.

## Teller Setup (US Banks)

To connect US bank accounts, you need a [Teller](https://teller.io) application:

1. **Create an account** at [teller.io](https://teller.io) and create a new application
2. **Copy your Application ID** — this is your `TELLER_APP_ID`
3. **Download your mTLS certificate** — `teller.zip` was downloaded when you signed up (contains `certificate.pem` and `private_key.pem`). If lost, regenerate from the Certificates section of the Teller Dashboard.
4. **Add credentials to `.env`**:
   ```bash
   TELLER_APP_ID=app_xxxxx
   TELLER_ENV=sandbox          # sandbox | development | production
   TELLER_CERT=/path/to/certificate.pem   # required for development/production
   TELLER_KEY=/path/to/private_key.pem    # required for development/production
   ```

> **Note:** Sandbox mode works without mTLS certificates and provides test data. You get 100 free enrollments on the developer plan.
>
> **Note:** You can also inline the PEM strings directly in `TELLER_CERT` and `TELLER_KEY` instead of pointing to file paths (use `\n` for newlines).

## Manual Setup

### 1. Configure `.env`

```bash
cp .env.example .env
```

Edit `.env` with your Enable Banking credentials, then generate the required keys:

```bash
# MCP_API_KEY
openssl rand -hex 32

# SESSION_ENCRYPTION_KEY (64 hex chars)
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run

```bash
source .venv/bin/activate
python3 src/server.py
```

### 4. Test

```bash
npx @modelcontextprotocol/inspector
```

Open http://localhost:6274 and connect to `http://localhost:3000/mcp` using "Streamable HTTP" transport. Pass `Authorization: Bearer <your-MCP_API_KEY>` header.

## Authentication

Set `MCP_API_KEY` to secure the server. All requests must include `Authorization: Bearer <MCP_API_KEY>`.

When running via `start.sh` (which uses `poke tunnel`), set `POKE_TUNNEL=1` to make `MCP_API_KEY` optional — the tunnel handles authentication. `start.sh` sets this automatically.

If `MCP_API_KEY` is not set and `POKE_TUNNEL` is not `1`, the server runs unauthenticated (with a warning). **Always set it in non-tunnel deployments.**

Enable Banking uses JWT-based authentication (not OAuth2 client credentials). Your application signs short-lived JWTs with the RSA private key registered in the Enable Banking dashboard. These JWTs are sent as Bearer tokens on every API request.

## Docker

```bash
docker compose up -d
```

Or use the pre-built image from GitHub Container Registry:

```bash
docker run -d \
  -p 3000:3000 \
  --env-file .env \
  -v poke-bank-data:/data \
  ghcr.io/kacperkwapisz/poke-bank:main
```

### Resource Limits

The server is mostly idle (lightweight HTTP + on-demand banking API calls). Recommended limits for container orchestrators:

| Resource | Reservation | Limit |
|----------|-------------|-------|
| Memory   | 64 MB       | 256 MB |
| CPU      | 0.1         | 0.5    |

## Routes

| Path | Method | Description |
|------|--------|-------------|
| `/mcp` | GET | Health check — returns `{"status": "ok"}` |
| `/mcp` | POST | MCP protocol endpoint |
| `/callback` | GET | Enable Banking redirect — auto-completes the authorization flow |
| `/connect/teller` | GET | Serves the Teller Connect widget page for US bank enrollment |
| `/callback/teller` | POST | Receives enrollment data from the Teller Connect widget |

All other paths return 404.

## MCP Tools

| Tool | Description |
|------|-------------|
| `get_auth_url` | Start the authorization flow — returns a URL for the user to open and a `session_id`. Use `provider='teller'` for US banks, `provider='enable_banking'` (default) for EU/Nordic. |
| `create_session` | Exchange the authorization code for a banking session (returns accounts) |
| `list_accounts` | List all bank accounts linked to a session |
| `get_transactions` | Get transactions for an account (optional date range filter) |
| `get_balances` | Get current balances for an account |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MCP_API_KEY` | Yes | Bearer token for MCP clients. Optional when `POKE_TUNNEL=1`. |
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
| `TELLER_APP_ID` | No | Teller application ID (enables US bank support via Teller) |
| `TELLER_ENV` | No | Teller environment: `sandbox`, `development`, or `production` (default: `sandbox`) |
| `TELLER_CERT` | No | Teller mTLS certificate — file path or inline PEM string (required for development/production) |
| `TELLER_KEY` | No | Teller mTLS private key — file path or inline PEM string (required for development/production) |
| `POKE_TUNNEL` | No | Set to `1` when using the Poke tunnel (disables MCP_API_KEY requirement) |
| `HOST_PORT` | No | Exposed port on the host (default: 3000) |
| `PORT` | No | Server port inside the container (default: 3000) |

## Authorization Flow

### Enable Banking (EU/Nordic)

1. Call `get_auth_url` with the bank name and country code
2. Open the returned `auth_url` in a browser and authorize
3. The bank redirects to `/callback` which auto-completes the session — no manual code copying needed
4. Use `list_accounts`, `get_transactions`, `get_balances` with the `session_id`

> **Fallback:** If the callback redirect doesn't work, you can also manually copy the `code` from the redirect URL and call `create_session` with the `code` and `session_id`.

### Teller (US)

1. Call `get_auth_url` with `provider='teller'`
2. Open the returned `auth_url` — the Teller Connect widget loads in the browser
3. User authenticates with their bank through the widget
4. On success, the page POSTs enrollment data to `/callback/teller` and shows "Connected"
5. Use `list_accounts`, `get_transactions`, `get_balances` with the `session_id`

If `POKE_WEBHOOK_URL` and `POKE_API_KEY` are set, a webhook is sent to Poke when a bank account is successfully connected (for both providers).

## Session Store

Session metadata (authorization IDs, account lists) is stored in an encrypted SQLite database at `/data/sessions.db` inside the container (or `./sessions.db` when running locally via `start.sh`). The `poke-bank-data` Docker volume persists this across restarts.

All session data is encrypted with AES-256-GCM using the `SESSION_ENCRYPTION_KEY`. The key never leaves your server.

## Poke Setup

Connect your MCP server to Poke at [poke.com/settings/connections](https://poke.com/settings/connections). Add the bearer token (`MCP_API_KEY`) in the connection auth settings.

When a bank account is connected, poke-bank can automatically notify Poke via webhook. Set `POKE_WEBHOOK_URL` and `POKE_API_KEY` in `.env` to enable this.

## License

MIT
