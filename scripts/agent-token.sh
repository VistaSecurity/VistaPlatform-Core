#!/usr/bin/env bash
# agent-token.sh — mint a short-lived GitHub App installation token for the
# `vista-agent` App, so an agent session acts under its own identity
# (CI_MERGE_FLOW_PLAN.md Phase 4, D3) and never under the owner's account.
#
# The App's private key lives OUTSIDE the repo and outside the agent's reach:
#   /etc/vista-agent/app.pem        (root:root 0400)
#   /etc/vista-agent/app.env        (root:root 0400):  APP_ID=…  INSTALLATION_ID=…
# and this script is run through sudo with a NOPASSWD rule for exactly it, so
# an agent obtains a ONE-HOUR token and never the key:
#   bwoodward ALL=(root) NOPASSWD: /usr/local/bin/vista-agent-token
#   (install: sudo install -m 0755 scripts/agent-token.sh /usr/local/bin/vista-agent-token)
#
# Usage:
#   export GH_TOKEN="$(sudo -n /usr/local/bin/vista-agent-token)"   # gh CLI
#   git -c "http.https://github.com/.extraheader=AUTHORIZATION: bearer $GH_TOKEN" push …
#   # or use the credential helper block printed by:  vista-agent-token --git-credential-helper
#
# Options:
#   --jwt-only           print the signed App JWT instead of exchanging it
#                        (used by scripts/test-agent-token.sh with a throwaway key)
#   --key <pem> --app-id <id> --installation-id <id>
#                        override the /etc/vista-agent defaults (tests; a laptop)
#
# What the token can do is decided by the App's permissions and installation
# (Contents RW on branches, Pull requests RW; main itself is protected under
# GitHub Pro so the App cannot push there) — not by anything here.

set -euo pipefail

KEY="${VISTA_AGENT_KEY:-/etc/vista-agent/app.pem}"
ENVFILE="${VISTA_AGENT_ENV:-/etc/vista-agent/app.env}"
APP_ID="${VISTA_AGENT_APP_ID:-}"
INSTALLATION_ID="${VISTA_AGENT_INSTALLATION_ID:-}"
API="${GITHUB_API_URL:-https://api.github.com}"
JWT_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --jwt-only) JWT_ONLY=1; shift ;;
    --key) KEY="$2"; shift 2 ;;
    --app-id) APP_ID="$2"; shift 2 ;;
    --installation-id) INSTALLATION_ID="$2"; shift 2 ;;
    --git-credential-helper)
      cat <<'EOF'
# Add to ~/.gitconfig (agents' HOME) so every push to github.com uses a fresh App token:
[credential "https://github.com"]
    helper = "!f() { echo username=x-access-token; echo password=$(sudo -n /usr/local/bin/vista-agent-token); }; f"
EOF
      exit 0 ;;
    *) echo "agent-token: unknown option $1" >&2; exit 2 ;;
  esac
done

if [ -z "$APP_ID" ] || [ -z "$INSTALLATION_ID" ]; then
  if [ -r "$ENVFILE" ]; then
    # shellcheck disable=SC1090
    . "$ENVFILE"
  fi
fi
[ -n "$APP_ID" ] || { echo "agent-token: APP_ID unset (no --app-id and $ENVFILE unreadable)" >&2; exit 2; }
[ -r "$KEY" ] || { echo "agent-token: private key $KEY is not readable (run via sudo as documented)" >&2; exit 2; }

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now="$(date +%s)"
header="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
# iat 60 s in the past tolerates clock skew; exp is the maximum GitHub allows (10 min).
payload="$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' "$((now - 60))" "$((now + 540))" "$APP_ID" | b64url)"
signature="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$KEY" -binary | b64url)"
jwt="${header}.${payload}.${signature}"

if [ "$JWT_ONLY" = 1 ]; then echo "$jwt"; exit 0; fi

[ -n "$INSTALLATION_ID" ] || { echo "agent-token: INSTALLATION_ID unset" >&2; exit 2; }
resp="$(curl -sS --fail --max-time 20 -X POST \
  -H "Authorization: Bearer $jwt" -H "Accept: application/vnd.github+json" \
  "$API/app/installations/$INSTALLATION_ID/access_tokens")" || { echo "agent-token: token exchange failed" >&2; exit 1; }
token="$(printf '%s' "$resp" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$token" ] || { echo "agent-token: no token in the response" >&2; exit 1; }
echo "$token"
