#!/usr/bin/env python3
"""poke-bank — FastMCP server exposing Enable Banking as MCP tools."""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from typing import Optional

import httpx
import uvicorn
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastmcp import FastMCP, Context
from fastmcp.server.auth import TokenVerifier, AccessToken
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("poke-bank")
logging.getLogger("httpx").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ENABLE_BANKING_BASE = os.environ.get(
    "ENABLE_BANKING_BASE", "https://api.enablebanking.com"
)
CLIENT_ID = os.environ.get("ENABLE_BANKING_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("ENABLE_BANKING_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("ENABLE_BANKING_REDIRECT_URI", "")

DB_PATH = os.environ.get("DB_PATH", "/data/sessions.db")

# Encryption key: 32 random bytes stored as hex in SESSION_ENCRYPTION_KEY env var.
# If not set a random key is generated (sessions won't survive restarts).
_raw_key = os.environ.get("SESSION_ENCRYPTION_KEY", "")
if _raw_key:
    ENCRYPTION_KEY = bytes.fromhex(_raw_key)
else:
    ENCRYPTION_KEY = secrets.token_bytes(32)
    logger.warning(
        "SESSION_ENCRYPTION_KEY not set — generating ephemeral key. "
        "Sessions will not survive restarts. Set SESSION_ENCRYPTION_KEY=<64 hex chars>."
    )

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class ApiKeyAuth(TokenVerifier):
    """Validates incoming requests against a static API key (MCP_API_KEY)."""

    def __init__(self, api_key: str):
        super().__init__()
        self._api_key = api_key

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self._api_key):
            return AccessToken(token=token, client_id="owner", scopes=["all"])
        return None


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class DropNonMCPRoutes:
    """Return 404 for any path outside /mcp — reveals nothing to scanners."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http" and not scope["path"].startswith("/mcp"):
            response = Response(status_code=404)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    """Per-IP sliding window rate limiter."""

    MAX_TRACKED_IPS = 1024

    def __init__(self, app: ASGIApp):
        self.app = app
        self.get_rpm = int(os.environ.get("RATE_LIMIT_GET_RPM", "30"))
        self.post_rpm = int(os.environ.get("RATE_LIMIT_POST_RPM", "120"))
        self.window = 60
        self._hits: dict[str, list[float]] = {}
        self._last_cleanup = time.monotonic()

    def _client_ip(self, scope: Scope) -> str:
        for header_name, header_val in scope.get("headers", []):
            if header_name == b"x-forwarded-for":
                parts = header_val.decode().split(",")
                return parts[-1].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _cleanup_stale(self, now: float) -> None:
        if now - self._last_cleanup < self.window:
            return
        self._last_cleanup = now
        cutoff = now - self.window
        stale = [ip for ip, ts in self._hits.items() if not ts or ts[-1] <= cutoff]
        for ip in stale:
            del self._hits[ip]
        if len(self._hits) > self.MAX_TRACKED_IPS:
            by_recency = sorted(self._hits, key=lambda ip: self._hits[ip][-1])
            for ip in by_recency[: len(self._hits) - self.MAX_TRACKED_IPS]:
                del self._hits[ip]

    def _is_limited(self, bucket: str, rpm: int) -> tuple[bool, int]:
        now = time.monotonic()
        self._cleanup_stale(now)
        timestamps = self._hits.get(bucket, [])
        cutoff = now - self.window
        timestamps = [t for t in timestamps if t > cutoff]
        self._hits[bucket] = timestamps
        if len(timestamps) >= rpm:
            oldest = timestamps[0]
            retry_after = int(oldest + self.window - now) + 1
            return True, max(retry_after, 1)
        timestamps.append(now)
        return False, 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = self._client_ip(scope)
        method = scope.get("method", "GET")
        if method == "POST":
            bucket, rpm = f"{ip}:post", self.post_rpm
        else:
            bucket, rpm = f"{ip}:get", self.get_rpm
        limited, retry_after = self._is_limited(bucket, rpm)
        if limited:
            response = JSONResponse(
                {"error": "rate_limited", "retry_after": retry_after},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Encrypted SQLite session store
# ---------------------------------------------------------------------------


def _encrypt(plaintext: str) -> str:
    """Encrypt plaintext string with AES-256-GCM. Returns base64-encoded blob."""
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def _decrypt(blob: str) -> str:
    """Decrypt base64-encoded AES-256-GCM blob. Returns plaintext string."""
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(ENCRYPTION_KEY)
    return aesgcm.decrypt(nonce, ct, None).decode()


def _db_init(db_path: str) -> None:
    """Create the sessions table if it doesn't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                encrypted_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def session_save(session_id: str, data: dict, db_path: str = DB_PATH) -> None:
    """Persist a session dict (encrypted) to SQLite."""
    now = int(time.time())
    encrypted = _encrypt(json.dumps(data))
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO sessions (session_id, encrypted_data, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                encrypted_data = excluded.encrypted_data,
                updated_at = excluded.updated_at
            """,
            (session_id, encrypted, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def session_load(session_id: str, db_path: str = DB_PATH) -> Optional[dict]:
    """Load and decrypt a session dict from SQLite. Returns None if not found."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT encrypted_data FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        return json.loads(_decrypt(row[0]))
    except Exception as e:
        logger.error("Failed to decrypt session %s: %s", session_id, e)
        return None


def session_delete(session_id: str, db_path: str = DB_PATH) -> None:
    """Remove a session from SQLite."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Enable Banking OAuth2 helpers
# ---------------------------------------------------------------------------


def _make_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


async def _token_request(payload: dict) -> dict:
    """POST to the Enable Banking token endpoint."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{ENABLE_BANKING_BASE}/token",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return resp.json()


async def _api_get(path: str, access_token: str, params: Optional[dict] = None) -> dict:
    """GET request to the Enable Banking API."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{ENABLE_BANKING_BASE}{path}",
            params=params,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def _refresh_if_needed(session: dict) -> dict:
    """Refresh the access token if it's within 60 seconds of expiry."""
    expires_at = session.get("expires_at", 0)
    if time.time() < expires_at - 60:
        return session  # still valid
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        raise ValueError("Session has no refresh_token and access token has expired.")
    token_data = await _token_request(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
    )
    session["access_token"] = token_data["access_token"]
    session["expires_at"] = int(time.time()) + token_data.get("expires_in", 3600)
    if "refresh_token" in token_data:
        session["refresh_token"] = token_data["refresh_token"]
    session_save(session["session_id"], session)
    return session


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(server: FastMCP):
    _db_init(DB_PATH)
    logger.info("poke-bank started (DB: %s)", DB_PATH)
    yield {}
    logger.info("poke-bank shut down")


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp_api_key = os.environ.get("MCP_API_KEY", "")
poke_tunnel_mode = os.environ.get("POKE_TUNNEL", "") == "1"

if mcp_api_key:
    auth = ApiKeyAuth(mcp_api_key)
elif poke_tunnel_mode:
    auth = None
    logger.info("POKE_TUNNEL=1 — MCP_API_KEY not required (tunnel handles auth).")
else:
    auth = None
    logger.warning(
        "MCP_API_KEY not set — server is unauthenticated. "
        "Set MCP_API_KEY or use POKE_TUNNEL=1."
    )

mcp = FastMCP("poke-bank", lifespan=lifespan, auth=auth)


@mcp.custom_route("/mcp", methods=["GET"])
async def health(request):
    return JSONResponse({"status": "ok", "service": "poke-bank"})


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    description=(
        "Start the Enable Banking OAuth2 flow. Returns an authorization URL "
        "that the user must open in their browser to grant access to their bank accounts. "
        "Also returns a session_id that you must pass to exchange_code after the redirect."
    )
)
async def get_auth_url(
    ctx: Context,
    aspsp_name: str,
    aspsp_country: str,
    psu_type: str = "personal",
) -> dict:
    """
    Generate an Enable Banking OAuth2 authorization URL.

    Args:
        aspsp_name: Bank / ASPSP name (e.g. 'Nordea', 'ING', 'Revolut').
        aspsp_country: Two-letter ISO country code of the bank (e.g. 'FI', 'DE', 'GB').
        psu_type: Payment service user type — 'personal' or 'business'. Default: 'personal'.

    Returns:
        auth_url: URL the user must open to authorize access.
        session_id: Opaque identifier — keep this, you'll need it for exchange_code.
    """
    if not CLIENT_ID or not REDIRECT_URI:
        return {"error": "ENABLE_BANKING_CLIENT_ID or ENABLE_BANKING_REDIRECT_URI not configured."}

    state = secrets.token_urlsafe(24)
    verifier, challenge = _make_pkce()
    session_id = secrets.token_urlsafe(32)

    # Persist pending session so exchange_code can retrieve the verifier
    session_save(
        session_id,
        {
            "session_id": session_id,
            "state": state,
            "code_verifier": verifier,
            "aspsp_name": aspsp_name,
            "aspsp_country": aspsp_country,
        },
    )

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "aisp",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "aspsp_name": aspsp_name,
        "aspsp_country": aspsp_country,
        "psu_type": psu_type,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    auth_url = f"{ENABLE_BANKING_BASE}/auth?{query}"

    return {
        "auth_url": auth_url,
        "session_id": session_id,
        "instructions": "Open auth_url in a browser. After authorizing, you'll be redirected to the redirect_uri with ?code=...&state=... — pass the code and session_id to exchange_code.",
    }


@mcp.tool(
    description=(
        "Exchange the authorization code received after the OAuth2 redirect for "
        "an access token. Pass the code from the redirect URL and the session_id "
        "returned by get_auth_url. Stores tokens encrypted in the local SQLite store."
    )
)
async def exchange_code(
    ctx: Context,
    code: str,
    session_id: str,
) -> dict:
    """
    Exchange OAuth2 authorization code for access + refresh tokens.

    Args:
        code: The 'code' query parameter from the Enable Banking redirect URL.
        session_id: The session_id returned by get_auth_url.

    Returns:
        success: True on success.
        session_id: Same session_id — use it with list_accounts, get_transactions, get_balances.
        expires_at: Unix timestamp when the access token expires.
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found. Call get_auth_url first."}

    try:
        token_data = await _token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code_verifier": session["code_verifier"],
            }
        )
    except httpx.HTTPStatusError as e:
        return {"error": f"Token exchange failed: {e.response.status_code} {e.response.text}"}

    session["access_token"] = token_data["access_token"]
    session["expires_at"] = int(time.time()) + token_data.get("expires_in", 3600)
    session["refresh_token"] = token_data.get("refresh_token", "")
    # Remove PKCE verifier — no longer needed
    session.pop("code_verifier", None)
    session.pop("state", None)
    session_save(session_id, session)

    return {
        "success": True,
        "session_id": session_id,
        "expires_at": session["expires_at"],
    }


@mcp.tool(
    description=(
        "List all bank accounts accessible via the given session. "
        "Call exchange_code first to obtain a valid session_id."
    )
)
async def list_accounts(
    ctx: Context,
    session_id: str,
) -> dict:
    """
    List all accounts linked to the Enable Banking session.

    Args:
        session_id: Session identifier from exchange_code.

    Returns:
        accounts: List of account objects (id, iban, currency, name, type, etc.).
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}

    try:
        session = await _refresh_if_needed(session)
        data = await _api_get("/accounts", session["access_token"])
    except httpx.HTTPStatusError as e:
        return {"error": f"API error: {e.response.status_code} {e.response.text}"}
    except ValueError as e:
        return {"error": str(e)}

    return {"accounts": data.get("accounts", data)}


@mcp.tool(
    description=(
        "Retrieve transactions for a specific bank account. "
        "Optionally filter by date range (ISO 8601: YYYY-MM-DD)."
    )
)
async def get_transactions(
    ctx: Context,
    session_id: str,
    account_id: str,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> dict:
    """
    Get transactions for a bank account.

    Args:
        session_id: Session identifier from exchange_code.
        account_id: Account identifier from list_accounts.
        date_from: Start date filter (YYYY-MM-DD). Optional.
        date_to: End date filter (YYYY-MM-DD). Optional.

    Returns:
        transactions: List of transaction objects.
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}

    try:
        session = await _refresh_if_needed(session)
        params: dict = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        data = await _api_get(
            f"/accounts/{account_id}/transactions",
            session["access_token"],
            params=params or None,
        )
    except httpx.HTTPStatusError as e:
        return {"error": f"API error: {e.response.status_code} {e.response.text}"}
    except ValueError as e:
        return {"error": str(e)}

    return {"transactions": data.get("transactions", data)}


@mcp.tool(
    description=(
        "Get current balances for a specific bank account."
    )
)
async def get_balances(
    ctx: Context,
    session_id: str,
    account_id: str,
) -> dict:
    """
    Get balances for a bank account.

    Args:
        session_id: Session identifier from exchange_code.
        account_id: Account identifier from list_accounts.

    Returns:
        balances: List of balance objects (type, amount, currency).
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}

    try:
        session = await _refresh_if_needed(session)
        data = await _api_get(
            f"/accounts/{account_id}/balances",
            session["access_token"],
        )
    except httpx.HTTPStatusError as e:
        return {"error": f"API error: {e.response.status_code} {e.response.text}"}
    except ValueError as e:
        return {"error": str(e)}

    return {"balances": data.get("balances", data)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    host = "0.0.0.0"
    logger.info("Starting poke-bank on %s:%d", host, port)
    app = mcp.http_app(
        middleware=[Middleware(DropNonMCPRoutes), Middleware(RateLimitMiddleware)],
        stateless_http=True,
    )
    uvicorn.run(app, host=host, port=port)
