#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# ── OTA update ────────────────────────────────────────────────────────────────
# Uses curl + Python stdlib tarfile — no git or unzip required.
#
# Flow:
#   1. Fetch latest GitHub Release tag via API (tiny JSON, 5 s timeout).
#   2. Compare against .poke_version (last installed version tag). Skip if
#      already up to date or if the remote is unreachable.
#   3. Download the release tarball only when an update exists (30 s timeout).
#   4. Extract with Python tarfile, stripping the GitHub top-level prefix and
#      skipping protected local files (.env, .venv, .poke_version).
#   5. Persist new version tag to .poke_version and reinstall deps if
#      requirements.txt changed.

if command -v curl &>/dev/null && command -v python3 &>/dev/null; then
  _OTA_REPO="kacperkwapisz/poke-bank"
  _VERSION_FILE=".poke_version"

  echo "Checking for updates..."

  # Step 1: fetch latest release tag and tarball URL (fail silently if offline)
  _RELEASE_JSON=$(curl -sf --max-time 5 \
    "https://api.github.com/repos/${_OTA_REPO}/releases/latest" \
    2>/dev/null || echo "")

  _REMOTE_TAG=""
  _TARBALL_URL=""
  if [ -n "$_RELEASE_JSON" ]; then
    _REMOTE_TAG=$(echo "$_RELEASE_JSON" | python3 -c \
      "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" \
      2>/dev/null || echo "")
    _TARBALL_URL=$(echo "$_RELEASE_JSON" | python3 -c \
      "import json,sys; print(json.load(sys.stdin).get('tarball_url',''))" \
      2>/dev/null || echo "")
  fi

  _LOCAL_TAG=$(cat "$_VERSION_FILE" 2>/dev/null || echo "")

  if [ -z "$_REMOTE_TAG" ]; then
    echo "  ℹ  Could not reach remote — continuing with local version."
    echo ""
  elif [ "$_REMOTE_TAG" = "$_LOCAL_TAG" ]; then
    echo "  ✓ Already up to date (${_LOCAL_TAG})"
    echo ""
  else
    if [ -n "$_LOCAL_TAG" ]; then
      echo "  ↳ Update found (${_LOCAL_TAG} → ${_REMOTE_TAG}), downloading..."
    else
      echo "  ↳ Update found (${_REMOTE_TAG}), downloading..."
    fi

    # Hash requirements.txt before extraction so we can detect changes
    _REQS_BEFORE=$(python3 -c \
      "import hashlib; print(hashlib.md5(open('requirements.txt','rb').read()).hexdigest())" \
      2>/dev/null || echo "")

    _TMP_TAR=$(mktemp /tmp/poke-bank-update.XXXXXX.tar.gz)

    if curl -sfL --max-time 30 \
         "$_TARBALL_URL" \
         -o "$_TMP_TAR" 2>/dev/null; then

      # Extract with Python: strip GitHub's top-level dir, skip protected paths
      python3 - "$_TMP_TAR" <<'PYEOF'
import sys, tarfile, os

archive = sys.argv[1]
# Files/dirs that must never be overwritten by an OTA update
PROTECTED = {'.env', '.venv', '.poke_version'}

try:
    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        if not members:
            sys.exit(0)
        # GitHub tarball root dir is e.g. "owner-repo-<sha>/"
        prefix = members[0].name.split('/')[0] + '/'
        for m in members:
            if not m.name.startswith(prefix):
                continue
            rel = m.name[len(prefix):]   # path relative to repo root
            if not rel:                   # skip the root dir entry itself
                continue
            top = rel.split('/')[0]
            if top in PROTECTED:
                continue
            m.name = rel
            try:
                tf.extract(m, path='.', set_attrs=False)
            except Exception:
                pass  # best-effort; don't abort on permission issues etc.
except Exception as e:
    print(f'  ⚠  Extraction error: {e}')
    sys.exit(1)
PYEOF

      # Persist new version tag so we don't re-download next run
      echo "$_REMOTE_TAG" > "$_VERSION_FILE"
      echo "  ✓ Updated to ${_REMOTE_TAG}"

      # Reinstall deps if requirements.txt changed
      _REQS_AFTER=$(python3 -c \
        "import hashlib; print(hashlib.md5(open('requirements.txt','rb').read()).hexdigest())" \
        2>/dev/null || echo "")
      if [ -n "$_REQS_BEFORE" ] && [ "$_REQS_BEFORE" != "$_REQS_AFTER" ]; then
        echo "  ↳ requirements.txt changed — reinstalling dependencies..."
        [ -d .venv ] && source .venv/bin/activate
        pip install -q -r requirements.txt
        echo "  ✓ Dependencies updated"
      fi
    else
      echo "  ℹ  Download failed — continuing with local version."
    fi

    rm -f "$_TMP_TAR"
    echo ""
  fi
fi

# ── One-time setup (skipped on subsequent runs) ───────────────────────────────

# 1. Python virtualenv + dependencies
if [ ! -d .venv ]; then
  echo "First run — setting up poke-bank..."
  echo ""
  echo "Creating Python virtualenv (.venv)..."
  python3 -m venv .venv
fi
source .venv/bin/activate

if ! python3 -c "import fastmcp" &>/dev/null 2>&1; then
  echo "Installing Python dependencies..."
  pip install -q -r requirements.txt
  echo "  ✓ Dependencies installed"
  echo ""
fi

# 2. .env — copy example if missing
if [ ! -f .env ]; then
  echo "Copying .env.example → .env..."
  cp .env.example .env
  echo "  ✓ .env created"
  echo ""
fi

# 3. Enable Banking credentials — prompt if placeholders remain
if grep -q 'your-app-id' .env 2>/dev/null; then
  echo "  ⚠  Enable Banking credentials not configured in .env"
  echo "     You need ENABLE_BANKING_APP_ID, ENABLE_BANKING_PRIVATE_KEY,"
  echo "     and ENABLE_BANKING_REDIRECT_URI from the Enable Banking dashboard."
  echo ""
  printf "  ENABLE_BANKING_APP_ID (leave blank to set manually later): "
  read -r _EB_APP_ID
  _EB_APP_ID=$(echo "$_EB_APP_ID" | tr -d '[:space:]')
  if [ -n "$_EB_APP_ID" ]; then
    _EB_APP_ID="$_EB_APP_ID" python3 - <<'PYEOF'
import os, re
val = os.environ['_EB_APP_ID']
with open('.env', 'r') as f:
    content = f.read()
content = re.sub(r'(?m)^ENABLE_BANKING_APP_ID=.*', f'ENABLE_BANKING_APP_ID={val}', content)
with open('.env', 'w') as f:
    f.write(content)
PYEOF
    echo "  ✓ ENABLE_BANKING_APP_ID saved to .env"
  fi
  echo ""
fi

# 4. Poke API key — read from 'poke login' credentials, inject into .env
if grep -q 'your-poke-api-key' .env 2>/dev/null || ! grep -Eq '^[[:space:]]*POKE_API_KEY=.+' .env 2>/dev/null; then
  POKE_CREDENTIALS_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/poke/credentials.json"
  POKE_TOKEN=""

  if [ -f "$POKE_CREDENTIALS_FILE" ]; then
    POKE_TOKEN=$(python3 -c "
import json, sys
try:
    data = json.load(open('$POKE_CREDENTIALS_FILE'))
    print(data.get('token', ''))
except Exception:
    print('')
" 2>/dev/null || true)
  fi

  if [ -n "$POKE_TOKEN" ]; then
    echo "  ✓ Poke API key detected from 'poke login'"
    POKE_TOKEN="$POKE_TOKEN" python3 - <<'PYEOF'
import os, re
token = os.environ['POKE_TOKEN']
with open('.env', 'r') as f:
    content = f.read()
# Uncomment POKE_API_KEY if commented out, then set value
content = re.sub(r'(?m)^#\s*POKE_API_KEY=.*', f'POKE_API_KEY={token}', content)
content = re.sub(r'(?m)^POKE_API_KEY=.*', f'POKE_API_KEY={token}', content)
with open('.env', 'w') as f:
    f.write(content)
PYEOF
    echo "  ✓ POKE_API_KEY written to .env"
    echo ""
  fi
fi

# 5. MCP_API_KEY — generate once and persist to .env (skip in tunnel mode)
if [ "${POKE_TUNNEL:-1}" != "1" ]; then
  if grep -Eq '^[[:space:]]*MCP_API_KEY=your-secret-key-here' .env 2>/dev/null \
     || ! grep -Eq '^[[:space:]]*MCP_API_KEY=.+' .env 2>/dev/null; then
    RANDOM_KEY=$(python3 -c "
import secrets, string
alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range(48)))
")
    RANDOM_KEY="$RANDOM_KEY" python3 - <<'PYEOF'
import os, re
new_key = os.environ['RANDOM_KEY']
with open('.env', 'r') as f:
    content = f.read()
new_content, n = re.subn(r'(?m)^[[:space:]]*MCP_API_KEY=.*', f'MCP_API_KEY={new_key}', content)
if n == 0:
    new_content += f'MCP_API_KEY={new_key}\n'
with open('.env', 'w') as f:
    f.write(new_content)
PYEOF
    echo "  ✓ MCP_API_KEY generated and saved to .env"
    echo ""
  fi
fi

# 6. SESSION_ENCRYPTION_KEY — generate once and persist to .env
if grep -Eq '^[[:space:]]*SESSION_ENCRYPTION_KEY=your-64-hex-char-key' .env 2>/dev/null \
   || ! grep -Eq '^[[:space:]]*SESSION_ENCRYPTION_KEY=[0-9a-fA-F]{64}' .env 2>/dev/null; then
  ENC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  ENC_KEY="$ENC_KEY" python3 - <<'PYEOF'
import os, re
new_key = os.environ['ENC_KEY']
with open('.env', 'r') as f:
    content = f.read()
new_content, n = re.subn(r'(?m)^[[:space:]]*SESSION_ENCRYPTION_KEY=.*', f'SESSION_ENCRYPTION_KEY={new_key}', content)
if n == 0:
    new_content += f'SESSION_ENCRYPTION_KEY={new_key}\n'
with open('.env', 'w') as f:
    f.write(new_content)
PYEOF
  echo "  ✓ SESSION_ENCRYPTION_KEY generated and saved to .env"
  echo ""
fi

# ── Load .env ─────────────────────────────────────────────────────────────────
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

# ── Tunnel-mode detection ─────────────────────────────────────────────────────
POKE_TUNNEL="${POKE_TUNNEL:-1}"

if [ "${POKE_TUNNEL}" != "1" ]; then
  : "${MCP_API_KEY:?MCP_API_KEY is not set — add it to .env or export it}"
else
  if [ -z "${MCP_API_KEY:-}" ]; then
    echo "  ℹ  MCP_API_KEY not set — server runs unauthenticated (safe: poke tunnel handles auth)."
  fi
export POKE_TUNNEL
fi

# ── Override DB_PATH for local runs ───────────────────────────────────────────
export DB_PATH="${DB_PATH:-./sessions.db}"

# ── Start server + tunnel ─────────────────────────────────────────────────────
echo "Starting poke-bank server..."
python3 src/server.py &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null" EXIT

sleep 2

echo "Starting tunnel to Poke..."
if command -v poke &>/dev/null; then
  poke tunnel http://localhost:3000/mcp --name "poke-bank"
else
  echo "  ℹ  'poke' binary not found in PATH — using npx poke (requires Node.js)."
  if ! command -v npx &>/dev/null; then
    echo "  ✗ Neither 'poke' nor 'npx' found. Install Node.js (nodejs.org) and run:"
    echo "      npm install -g poke   OR   npx poke tunnel ..."
    exit 1
  fi
  npx --yes poke tunnel http://localhost:3000/mcp --name "poke-bank"
fi
