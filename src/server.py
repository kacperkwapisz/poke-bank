#!/usr/bin/env python3
"""poke-bank — FastMCP server exposing Enable Banking and Teller as MCP tools."""

import asyncio
import base64
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import jwt
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
APP_ID = os.environ.get("ENABLE_BANKING_APP_ID", "")
REDIRECT_URI = os.environ.get("ENABLE_BANKING_REDIRECT_URI", "")
POKE_WEBHOOK_URL = os.environ.get("POKE_WEBHOOK_URL", "https://poke.com/api/v1/inbound/api-message")
POKE_API_KEY = os.environ.get("POKE_API_KEY", "")

# Teller credentials (optional — for US bank support)
TELLER_APP_ID = os.environ.get("TELLER_APP_ID", "")
TELLER_ENV = os.environ.get("TELLER_ENV", "sandbox")  # sandbox | development | production

# mTLS certificate for Teller API — PEM file paths or inline PEM strings
_teller_cert_raw = os.environ.get("TELLER_CERT", "")
_teller_key_raw = os.environ.get("TELLER_KEY", "")


def _resolve_pem(raw: str) -> str | None:
    """Return a file path for a PEM value (file path or inline string)."""
    if not raw:
        return None
    if os.path.isfile(raw):
        return raw
    # Treat as inline PEM — handle escaped newlines from env vars / Docker
    content = raw.replace("\\n", "\n")
    if "BEGIN" not in content:
        return None
    import tempfile
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    f.write(content)
    f.close()
    return f.name


TELLER_CERT = _resolve_pem(_teller_cert_raw)
TELLER_KEY = _resolve_pem(_teller_key_raw)

TELLER_API_BASE = "https://api.teller.io"

# RSA private key for signing JWTs — PEM string or path to file.
_pk_raw = os.environ.get("ENABLE_BANKING_PRIVATE_KEY", "")
if _pk_raw and os.path.isfile(_pk_raw):
    with open(_pk_raw) as f:
        PRIVATE_KEY = f.read()
else:
    # Handle escaped newlines from env vars / Docker
    PRIVATE_KEY = _pk_raw.replace("\\n", "\n")

# Fallback consent validity in days (used when ASPSP lookup fails).
CONSENT_VALIDITY_DAYS_FALLBACK = int(os.environ.get("CONSENT_VALIDITY_DAYS", "90"))

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
        if scope["type"] == "http" and not scope["path"].startswith(("/mcp", "/callback", "/connect")):
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


def session_find_by_state(state: str, db_path: str = DB_PATH) -> Optional[dict]:
    """Find a pending session by its OAuth state parameter."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT session_id, encrypted_data FROM sessions").fetchall()
    finally:
        conn.close()
    for sid, blob in rows:
        try:
            data = json.loads(_decrypt(blob))
        except Exception:
            continue
        if data.get("state") == state:
            return data
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
# Enable Banking API helpers
# ---------------------------------------------------------------------------


def _make_jwt() -> str:
    """Create a short-lived RS256 JWT for Enable Banking API authentication."""
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 600,  # 10 minutes
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": APP_ID})


def _api_headers() -> dict[str, str]:
    """Return authorization headers for Enable Banking API requests."""
    return {
        "Authorization": f"Bearer {_make_jwt()}",
        "Content-Type": "application/json",
    }


async def _api_post(path: str, body: dict) -> dict:
    """POST JSON to the Enable Banking API."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{ENABLE_BANKING_BASE}{path}",
            json=body,
            headers=_api_headers(),
        )
        resp.raise_for_status()
        return resp.json()


async def _api_get(path: str, params: Optional[dict] = None) -> dict:
    """GET request to the Enable Banking API."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{ENABLE_BANKING_BASE}{path}",
            params=params,
            headers=_api_headers(),
        )
        resp.raise_for_status()
        return resp.json()


async def _get_max_consent_seconds(aspsp_name: str, aspsp_country: str) -> Optional[int]:
    """Fetch the maximum_consent_validity (seconds) for an ASPSP, or None on failure."""
    try:
        data = await _api_get("/aspsps", params={"country": aspsp_country})
        for aspsp in data.get("aspsps", []):
            if aspsp.get("name") == aspsp_name:
                return aspsp.get("maximum_consent_validity")
    except (httpx.HTTPStatusError, httpx.RequestError):
        pass
    return None


# ---------------------------------------------------------------------------
# Teller API helpers
# ---------------------------------------------------------------------------


async def _teller_get(path: str, access_token: str) -> list | dict:
    """GET from Teller API with mTLS + HTTP Basic Auth."""
    auth = httpx.BasicAuth(username=access_token, password="")
    kwargs: dict = {"timeout": 30, "auth": auth}
    if TELLER_CERT and TELLER_KEY:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_cert_chain(certfile=TELLER_CERT, keyfile=TELLER_KEY)
        kwargs["verify"] = ssl_ctx
    async with httpx.AsyncClient(**kwargs) as client:
        resp = await client.get(f"{TELLER_API_BASE}{path}")
        resp.raise_for_status()
        return resp.json()


# UUID or hex string — rejects path traversal characters.
_ACCOUNT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _valid_account_id(account_id: str) -> bool:
    return bool(account_id and _ACCOUNT_ID_RE.match(account_id))


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


# Incomplete sessions older than this (seconds) are purged on startup.
_STALE_SESSION_AGE = 24 * 3600  # 1 day


def _purge_stale_sessions(db_path: str = DB_PATH) -> int:
    """Delete sessions older than _STALE_SESSION_AGE that were never activated."""
    cutoff = int(time.time()) - _STALE_SESSION_AGE
    conn = sqlite3.connect(db_path)
    deleted = 0
    try:
        rows = conn.execute(
            "SELECT session_id, encrypted_data FROM sessions WHERE updated_at < ?",
            (cutoff,),
        ).fetchall()
        for sid, blob in rows:
            try:
                data = json.loads(_decrypt(blob))
            except Exception:
                # Can't decrypt — stale, delete it
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
                deleted += 1
                continue
            if not data.get("eb_session_id") and not data.get("teller_access_token"):
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
                deleted += 1
        conn.commit()
    finally:
        conn.close()
    return deleted


@asynccontextmanager
async def lifespan(server: FastMCP):
    _db_init(DB_PATH)
    purged = _purge_stale_sessions()
    if purged:
        logger.info("Purged %d stale sessions", purged)
    if TELLER_APP_ID:
        logger.info("Teller enabled (env: %s)", TELLER_ENV)
        if TELLER_ENV != "sandbox" and (not TELLER_CERT or not TELLER_KEY):
            logger.warning(
                "Teller env is '%s' but TELLER_CERT/TELLER_KEY not set — "
                "API calls will fail without mTLS certificates.",
                TELLER_ENV,
            )
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


async def forward_to_poke(session_id: str, session: dict, accounts: list) -> bool:
    """Send a webhook to Poke when a bank account is connected."""
    provider = session.get("provider", "enable_banking")
    if provider == "teller":
        aspsp_name = session.get("institution_name", "Teller")
        aspsp_country = "US"
        account_items = [
            {
                "uid": acc.get("id"),
                "iban": None,
                "currency": acc.get("currency", "USD"),
                "name": acc.get("name"),
            }
            for acc in accounts
        ]
    else:
        aspsp_name = session.get("aspsp_name", "")
        aspsp_country = session.get("aspsp_country", "")
        account_items = [
            {
                "uid": acc.get("uid"),
                "iban": acc.get("iban"),
                "currency": acc.get("currency"),
                "name": acc.get("account_name") or acc.get("name"),
            }
            for acc in accounts
        ]
    payload = {
        "event": "bank_account_connected",
        "session_id": session_id,
        "aspsp_name": aspsp_name,
        "aspsp_country": aspsp_country,
        "account_count": len(accounts),
        "accounts": account_items,
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }
    headers = {"Content-Type": "application/json"}
    headers["Authorization"] = f"Bearer {POKE_API_KEY}"

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                resp = await http.post(POKE_WEBHOOK_URL, json=payload, headers=headers)
                resp.raise_for_status()
                logger.info("Webhook sent to Poke (status %d)", resp.status_code)
                return True
        except Exception as e:
            logger.warning("Poke webhook attempt %d failed: %s", attempt + 1, e)
            if attempt == 0:
                await asyncio.sleep(2)
    return False


@mcp.custom_route("/callback", methods=["GET"])
async def callback(request):
    """Handle the Enable Banking redirect — auto-complete the session."""
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")

    _page = (
        "<html><body style='font-family:system-ui;max-width:480px;margin:40px auto;text-align:center'>"
        "{body}</body></html>"
    )

    if not code or not state:
        return Response(
            content=_page.format(body="<h1>Error</h1><p>Missing code or state parameter.</p>"),
            media_type="text/html",
            status_code=400,
        )

    # Find the pending session by state
    session = session_find_by_state(state)
    if not session:
        return Response(
            content=_page.format(body="<h1>Error</h1><p>Session not found or expired.</p>"),
            media_type="text/html",
            status_code=404,
        )

    session_id = session["session_id"]

    # Exchange the code for an Enable Banking session
    try:
        data = await _api_post("/sessions", {"code": code})
    except httpx.HTTPStatusError as e:
        logger.error("Callback session creation failed: %s %s", e.response.status_code, e.response.text)
        return Response(
            content=_page.format(body="<h1>Error</h1><p>Bank session creation failed. Please try again.</p>"),
            media_type="text/html",
            status_code=502,
        )
    except httpx.RequestError as e:
        logger.error("Callback network error: %s", e)
        return Response(
            content=_page.format(body="<h1>Error</h1><p>Network error. Please try again.</p>"),
            media_type="text/html",
            status_code=502,
        )

    eb_session_id = data.get("session_id", data.get("sessionId", ""))
    accounts = data.get("accounts", [])

    session["eb_session_id"] = eb_session_id
    session["accounts"] = accounts
    session.pop("state", None)
    session.pop("authorization_id", None)
    session_save(session_id, session)

    if POKE_API_KEY:
        asyncio.create_task(forward_to_poke(session_id, session, accounts))

    account_count = len(accounts)
    return Response(
        content=_page.format(
            body=(
                "<h1>Connected</h1>"
                f"<p>{account_count} account{'s' if account_count != 1 else ''} linked.</p>"
                "<p style='color:#666;font-size:14px'>You can close this tab and return to your assistant.</p>"
            )
        ),
        media_type="text/html",
    )


@mcp.custom_route("/connect/teller", methods=["GET"])
async def connect_teller(request):
    """Serve the Teller Connect widget page."""
    session_id = request.query_params.get("session_id", "")

    _page = (
        "<html><body style='font-family:system-ui;max-width:480px;margin:40px auto;text-align:center'>"
        "{body}</body></html>"
    )

    if not session_id:
        return Response(
            content=_page.format(body="<h1>Error</h1><p>Missing session_id parameter.</p>"),
            media_type="text/html",
            status_code=400,
        )

    session = session_load(session_id)
    if not session or session.get("provider") != "teller":
        return Response(
            content=_page.format(body="<h1>Error</h1><p>Session not found or expired.</p>"),
            media_type="text/html",
            status_code=404,
        )

    # Reject already-activated sessions
    if session.get("teller_access_token"):
        return Response(
            content=_page.format(
                body="<h1>Already Connected</h1><p>This session is already linked. You can close this tab.</p>"
            ),
            media_type="text/html",
        )

    # Build the callback URL from the request origin
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme or "http")
    host = request.headers.get("host", "localhost")
    callback_url = f"{scheme}://{host}/callback/teller"

    # Escape values for safe embedding in JS string literals
    def _js_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n").replace("<", "\\x3c")

    safe_app_id = _js_escape(TELLER_APP_ID)
    safe_env = _js_escape(TELLER_ENV)
    safe_session_id = _js_escape(session_id)
    safe_callback = _js_escape(callback_url)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Bank Account</title>
<style>
  body {{ font-family: system-ui; max-width: 480px; margin: 40px auto; text-align: center; }}
  #status {{ margin-top: 20px; color: #666; font-size: 14px; }}
  #error {{ color: #c00; display: none; margin-top: 20px; }}
</style>
</head>
<body>
<h1 id="heading">Connecting...</h1>
<p id="status">Loading Teller Connect...</p>
<p id="error"></p>
<script src="https://cdn.teller.io/connect/connect.js"></script>
<script>
  var tellerConnect = TellerConnect.setup({{
    applicationId: "{safe_app_id}",
    environment: "{safe_env}",
    onInit: function() {{
      document.getElementById("status").textContent = "Select your bank...";
    }},
    onSuccess: function(enrollment) {{
      document.getElementById("heading").textContent = "Connecting...";
      document.getElementById("status").textContent = "Saving your connection...";
      fetch("{safe_callback}", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{
          session_id: "{safe_session_id}",
          access_token: enrollment.accessToken,
          enrollment_id: enrollment.enrollment.id,
          institution_name: enrollment.enrollment.institution.name
        }})
      }}).then(function(r) {{ return r.json(); }})
        .then(function(data) {{
          if (data.success) {{
            document.getElementById("heading").textContent = "Connected";
            document.getElementById("status").textContent =
              data.account_count + " account" + (data.account_count !== 1 ? "s" : "") + " linked. You can close this tab.";
          }} else {{
            document.getElementById("heading").textContent = "Error";
            document.getElementById("error").style.display = "block";
            document.getElementById("error").textContent = data.error || "Connection failed.";
            document.getElementById("status").textContent = "";
          }}
        }})
        .catch(function(err) {{
          document.getElementById("heading").textContent = "Error";
          document.getElementById("error").style.display = "block";
          document.getElementById("error").textContent = "Network error: " + err.message;
          document.getElementById("status").textContent = "";
        }});
    }},
    onExit: function() {{
      if (document.getElementById("heading").textContent === "Connecting...") {{
        document.getElementById("heading").textContent = "Cancelled";
        document.getElementById("status").textContent = "You closed the widget. Refresh to try again.";
      }}
    }}
  }});
  tellerConnect.open();
</script>
</body>
</html>"""

    return Response(content=html, media_type="text/html")


@mcp.custom_route("/callback/teller", methods=["POST"])
async def callback_teller(request):
    """Receive enrollment data from the Teller Connect widget."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    session_id = body.get("session_id", "")
    access_token = body.get("access_token", "")
    enrollment_id = body.get("enrollment_id", "")
    institution_name = body.get("institution_name", "")

    if not session_id or not access_token:
        return JSONResponse({"error": "session_id and access_token are required."}, status_code=400)

    session = session_load(session_id)
    if not session or session.get("provider") != "teller":
        return JSONResponse({"error": "Session not found or expired."}, status_code=404)

    if session.get("teller_access_token"):
        return JSONResponse({"error": "Session already activated."}, status_code=409)

    # Fetch accounts from Teller API
    try:
        accounts = await _teller_get("/accounts", access_token)
    except httpx.HTTPStatusError as e:
        logger.error("Teller accounts fetch failed: %s %s", e.response.status_code, e.response.text)
        return JSONResponse({"error": "Failed to fetch accounts from Teller."}, status_code=502)
    except httpx.RequestError as e:
        logger.error("Teller accounts network error: %s", e)
        return JSONResponse({"error": "Network error contacting Teller."}, status_code=502)

    session["teller_access_token"] = access_token
    session["teller_enrollment_id"] = enrollment_id
    session["institution_name"] = institution_name
    session["accounts"] = accounts
    session_save(session_id, session)

    if POKE_API_KEY:
        asyncio.create_task(forward_to_poke(session_id, session, accounts))

    return JSONResponse({"success": True, "account_count": len(accounts)})


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    description=(
        "Start the bank authorization flow. Returns an authorization URL "
        "that the user must open in their browser to grant access to their bank accounts. "
        "Also returns a session_id. Use provider='teller' for US banks, "
        "or provider='enable_banking' (default) for EU/Nordic banks."
    )
)
async def get_auth_url(
    ctx: Context,
    aspsp_name: str = "",
    aspsp_country: str = "",
    psu_type: str = "personal",
    provider: str = "enable_banking",
) -> dict:
    """
    Start bank authorization — get a URL for the user to open.

    Args:
        aspsp_name: Bank / ASPSP name (e.g. 'Nordea', 'ING'). Required for enable_banking, ignored for teller.
        aspsp_country: Two-letter ISO country code (e.g. 'FI', 'DE'). Required for enable_banking, ignored for teller.
        psu_type: Payment service user type — 'personal' or 'business'. Default: 'personal'. Enable Banking only.
        provider: 'enable_banking' (default) for EU/Nordic banks, 'teller' for US banks.

    Returns:
        auth_url: URL the user must open to authorize access.
        session_id: Opaque identifier for subsequent tool calls.
    """
    if provider == "teller":
        return _get_auth_url_teller()
    if provider != "enable_banking":
        return {"error": f"Unknown provider '{provider}'. Use 'enable_banking' or 'teller'."}
    return await _get_auth_url_enable_banking(aspsp_name, aspsp_country, psu_type)


def _get_auth_url_teller() -> dict:
    """Create a Teller Connect URL for US bank authorization."""
    if not TELLER_APP_ID:
        return {"error": "TELLER_APP_ID must be set."}
    if not REDIRECT_URI:
        return {"error": "ENABLE_BANKING_REDIRECT_URI must be set (used as base for Teller connect URL)."}

    local_session_id = secrets.token_urlsafe(32)

    # Derive the connect URL from the Enable Banking redirect URI base
    base_url = REDIRECT_URI.rsplit("/", 1)[0]
    connect_url = f"{base_url}/connect/teller?session_id={local_session_id}"

    session_save(
        local_session_id,
        {
            "session_id": local_session_id,
            "provider": "teller",
        },
    )

    return {
        "auth_url": connect_url,
        "session_id": local_session_id,
        "instructions": (
            "Open auth_url in a browser. You'll see the Teller Connect widget "
            "to authenticate with your bank. After connecting, use list_accounts "
            "to see your linked accounts."
        ),
    }


async def _get_auth_url_enable_banking(
    aspsp_name: str, aspsp_country: str, psu_type: str
) -> dict:
    """Create an Enable Banking authorization URL for EU/Nordic banks."""
    if not APP_ID or not PRIVATE_KEY:
        return {
            "error": "ENABLE_BANKING_APP_ID and ENABLE_BANKING_PRIVATE_KEY must be set."
        }
    if not REDIRECT_URI:
        return {"error": "ENABLE_BANKING_REDIRECT_URI must be set."}
    if not aspsp_name or not aspsp_country:
        return {"error": "aspsp_name and aspsp_country are required for enable_banking provider."}

    max_seconds = await _get_max_consent_seconds(aspsp_name, aspsp_country)
    if max_seconds:
        consent_duration = timedelta(seconds=max_seconds)
    else:
        consent_duration = timedelta(days=CONSENT_VALIDITY_DAYS_FALLBACK)

    state = secrets.token_urlsafe(24)
    local_session_id = secrets.token_urlsafe(32)
    valid_until = (
        datetime.now(timezone.utc) + consent_duration
    ).isoformat()

    body = {
        "access": {"valid_until": valid_until},
        "aspsp": {"name": aspsp_name, "country": aspsp_country},
        "state": state,
        "redirect_url": REDIRECT_URI,
        "psu_type": psu_type,
    }

    try:
        data = await _api_post("/auth", body)
    except httpx.HTTPStatusError as e:
        return {
            "error": f"Enable Banking /auth failed: {e.response.status_code} {e.response.text}"
        }
    except httpx.RequestError as e:
        return {"error": f"Network error contacting Enable Banking: {e}"}

    auth_url = data.get("url", "")
    authorization_id = data.get("authorization_id", "")

    session_save(
        local_session_id,
        {
            "session_id": local_session_id,
            "provider": "enable_banking",
            "state": state,
            "authorization_id": authorization_id,
            "aspsp_name": aspsp_name,
            "aspsp_country": aspsp_country,
        },
    )

    return {
        "auth_url": auth_url,
        "session_id": local_session_id,
        "instructions": (
            "Open auth_url in a browser. After authorizing, you'll be redirected "
            "to the redirect_url with ?code=... — pass the code and this session_id "
            "to create_session."
        ),
    }


@mcp.tool(
    description=(
        "Create an Enable Banking session using the authorization code from the redirect. "
        "Pass the code from the redirect URL and the session_id returned by get_auth_url. "
        "Returns the list of authorized bank accounts."
    )
)
async def create_session(
    ctx: Context,
    code: str,
    session_id: str,
) -> dict:
    """
    Exchange the authorization code for an Enable Banking session.

    Args:
        code: The 'code' query parameter from the Enable Banking redirect URL.
        session_id: The session_id returned by get_auth_url.

    Returns:
        success: True on success.
        session_id: Same session_id — use it with list_accounts, get_transactions, get_balances.
        accounts: List of authorized bank accounts.
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found. Call get_auth_url first."}

    try:
        data = await _api_post("/sessions", {"code": code})
    except httpx.HTTPStatusError as e:
        return {
            "error": f"Session creation failed: {e.response.status_code} {e.response.text}"
        }
    except httpx.RequestError as e:
        return {"error": f"Network error contacting Enable Banking: {e}"}

    # Enable Banking returns a session_id and accounts list
    eb_session_id = data.get("session_id", data.get("sessionId", ""))
    accounts = data.get("accounts", [])

    session["eb_session_id"] = eb_session_id
    session["accounts"] = accounts
    # Clean up auth-only fields
    session.pop("state", None)
    session.pop("authorization_id", None)
    session_save(session_id, session)

    return {
        "success": True,
        "session_id": session_id,
        "accounts": accounts,
    }


@mcp.tool(
    description=(
        "List all bank accounts accessible via the given session. "
        "Call create_session first to obtain a valid session_id."
    )
)
async def list_accounts(
    ctx: Context,
    session_id: str,
) -> dict:
    """
    List all accounts linked to the Enable Banking session.

    Args:
        session_id: Session identifier from create_session.

    Returns:
        accounts: List of account objects (uid, iban, currency, name, type, etc.).
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}

    accounts = session.get("accounts")
    if accounts is not None:
        return {"accounts": accounts}

    return {"error": "No accounts in session. Call create_session first."}


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
        session_id: Session identifier from create_session.
        account_id: Account uid from list_accounts.
        date_from: Start date filter (YYYY-MM-DD). Optional.
        date_to: End date filter (YYYY-MM-DD). Optional.

    Returns:
        transactions: List of transaction objects.
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}

    provider = session.get("provider", "enable_banking")

    if provider == "teller":
        access_token = session.get("teller_access_token")
        if not access_token:
            return {"error": "Session not activated. Complete the Teller Connect flow first."}
        if not _valid_account_id(account_id):
            return {"error": "Invalid account_id."}

        try:
            data = await _teller_get(f"/accounts/{account_id}/transactions", access_token)
        except httpx.HTTPStatusError as e:
            return {"error": f"Teller API error: {e.response.status_code} {e.response.text}"}
        except httpx.RequestError as e:
            return {"error": f"Network error: {e}"}

        # Teller returns a list directly; filter by date client-side if requested
        transactions = data if isinstance(data, list) else data.get("transactions", [])
        if date_from:
            transactions = [t for t in transactions if t.get("date", "") >= date_from]
        if date_to:
            transactions = [t for t in transactions if t.get("date", "") <= date_to]

        return {"transactions": transactions}

    # Enable Banking path
    if not session.get("eb_session_id"):
        return {"error": "Session not activated. Call create_session first."}
    if not _valid_account_id(account_id):
        return {"error": "Invalid account_id."}

    try:
        params: dict = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        data = await _api_get(
            f"/accounts/{account_id}/transactions",
            params=params or None,
        )
    except httpx.HTTPStatusError as e:
        return {"error": f"API error: {e.response.status_code} {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error: {e}"}

    return {"transactions": data.get("transactions", data)}


@mcp.tool(description="Get current balances for a specific bank account.")
async def get_balances(
    ctx: Context,
    session_id: str,
    account_id: str = "",
) -> dict:
    """
    Get balances for a bank account.

    Args:
        session_id: Session identifier from create_session.
        account_id: Account uid from list_accounts.

    Returns:
        balances: List of balance objects (type, amount, currency).
    """
    session = session_load(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}

    provider = session.get("provider", "enable_banking")

    if provider == "teller":
        access_token = session.get("teller_access_token")
        if not access_token:
            return {"error": "Session not activated. Complete the Teller Connect flow first."}
        if not _valid_account_id(account_id):
            return {"error": "Invalid account_id."}

        try:
            data = await _teller_get(f"/accounts/{account_id}/balances", access_token)
        except httpx.HTTPStatusError as e:
            return {"error": f"Teller API error: {e.response.status_code} {e.response.text}"}
        except httpx.RequestError as e:
            return {"error": f"Network error: {e}"}

        return {"balances": data}

    # Enable Banking path
    if not session.get("eb_session_id"):
        return {"error": "Session not activated. Call create_session first."}
    if not _valid_account_id(account_id):
        return {"error": "Invalid account_id."}

    try:
        data = await _api_get(f"/accounts/{account_id}/balances")
    except httpx.HTTPStatusError as e:
        return {"error": f"API error: {e.response.status_code} {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error: {e}"}

    return {"balances": data.get("balances", data.get("balance", data))}


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
