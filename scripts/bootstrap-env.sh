#!/usr/bin/env bash
# Create a .env for a local VistaPlatform deployment, with real secrets.
#
# env.example ships memorable placeholders (crypto_pass_dev, admin123,
# dev-secret-key-change-in-production) so the file reads clearly and diffs
# cleanly. Those values are published in this repository, which makes them
# useless as secrets: a deployment that keeps them has a JWT signing key,
# a service-auth secret and a database password that anyone can look up.
#
# So this script copies env.example and replaces every known placeholder with
# a freshly generated random value. Run it once before `docker compose up`.
#
#   ./scripts/bootstrap-env.sh
#
# It will not overwrite an existing .env. To rotate, delete .env and re-run —
# note that rotating POSTGRES_PASSWORD against an existing database volume
# will lock you out of it, because the password was baked in at init time.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo "✅ .env already exists — leaving it alone."
  echo
  echo "   To start over:  docker compose down -v && rm .env && ./scripts/bootstrap-env.sh"
  echo
  echo "   The -v matters. Postgres bakes POSTGRES_PASSWORD in when its volume is"
  echo "   first initialised and never reads it again, so a new .env against an old"
  echo "   volume fails every connection with 'password authentication failed for"
  echo "   user crypto_user' — which looks like a config bug and is not one."
  exit 0
fi

if [[ ! -f env.example ]]; then
  echo "❌ env.example not found. Run this from a VistaPlatform checkout." >&2
  exit 1
fi

for tool in openssl awk; do
  command -v "$tool" >/dev/null 2>&1 || { echo "❌ $tool is required but not installed." >&2; exit 1; }
done

cp env.example .env

# Only values that still match the placeholder EXACTLY are rewritten, so this
# stays safe to re-run against a partially hand-edited file.
#
# Alphanumeric-only output: these land in URLs (redis://:pass@host),
# docker-compose interpolation and psql connection strings, where a raw
# base64 '/' or '+' silently truncates or corrupts the value. Hex costs a
# little entropy density and buys not having to debug that.
rotate() {
  local var="$1" placeholder="$2" bytes="${3:-32}" generated tmp
  local current

  # Assert the placeholder is real before deciding it does not match.
  #
  # This function is a no-op when the value differs from the placeholder, which
  # is correct for a user-edited .env and catastrophic when the placeholder
  # itself has gone stale: env.example changes, the literal here stops matching
  # anything, and the rotation silently stops happening. INFLUXDB_PASSWORD spent
  # its life this way — the script looked for 'influx_pass_dev' while
  # env.example said 'adminpass123', so every deployment shipped a published
  # InfluxDB admin password and the script cheerfully reported success.
  #
  # env.example is ours, so we can check: if the placeholder is not in it, the
  # bug is in this file and it is not safe to continue.
  if ! grep -qE "^${var}=${placeholder}$" env.example; then
    echo "❌ ${var}: this script expects the placeholder '${placeholder}', which is not in env.example." >&2
    echo "   Update the rotate line to match env.example. Refusing to write a .env with an" >&2
    echo "   un-rotated secret in it." >&2
    exit 1
  fi

  current=$(grep -E "^${var}=" .env 2>/dev/null | head -1 | cut -d= -f2- || true)
  [[ "$current" == "$placeholder" ]] || return 0
  generated=$(openssl rand -hex "$bytes")
  tmp=$(mktemp "${TMPDIR:-/tmp}/env.XXXXXX")
  awk -v var="$var" -v val="$generated" \
      '{ if (index($0, var "=") == 1) print var "=" val; else print $0 }' \
      .env > "$tmp" && mv "$tmp" .env
  echo "   🔐 $var"
}

echo "📝 Generating .env from env.example with fresh secrets..."
rotate POSTGRES_PASSWORD       crypto_pass_dev                              24
rotate REDIS_PASSWORD          redis_pass_dev                               24
rotate NATS_PASSWORD           nats_pass_dev                                24
rotate INFLUXDB_PASSWORD       adminpass123                                 24
rotate INFLUXDB_TOKEN          dev-token-1234567890                         32
rotate JWT_SECRET              dev-secret-key-change-in-production          32
rotate ENCRYPTION_MASTER_KEY   dev-master-key-change-in-production          32
rotate INTERNAL_AUTH_SECRET    dev-internal-auth-secret-change-in-production 32
rotate GRAFANA_ADMIN_PASSWORD  admin123                                     16

# env.example pins 20 host ports into the 4xxxx range so this stack can run beside
# other things on a developer's machine. That is a workstation concern, and it
# quietly contradicts the docs: a user follows a README that says :3000 and finds
# the UI on :43000.
#
# Only the three the README actually names are normalised. Everything reaches the
# backends through the gateway, so publishing all sixteen service ports on the
# host buys a stranger nothing and costs them a collision with whatever else is
# already listening. Those stay on their offsets.
tmp=$(mktemp "${TMPDIR:-/tmp}/env.XXXXXX")
awk '/^(API_GATEWAY|WEB_UI|ADMIN_UI)_HOST_PORT=/ { print "# " $0; next } { print }' .env > "$tmp" && mv "$tmp" .env
echo "   🔌 gateway/web-ui/admin-ui on the documented 8080/3000/3006"
echo "      (set API_GATEWAY_HOST_PORT / WEB_UI_HOST_PORT / ADMIN_UI_HOST_PORT in"
echo "       .env if any of those three is already taken on your machine)"

# INTERNAL_AUTH_SECRET is what every service-to-service HMAC is signed with.
# env.example may omit it entirely depending on how the file was last edited,
# and an absent value is worse than a placeholder: the services start, agree
# that the shared secret is the empty string, and authenticate happily.
if ! grep -q "^INTERNAL_AUTH_SECRET=" .env; then
  echo "INTERNAL_AUTH_SECRET=$(openssl rand -hex 32)" >> .env
  echo "   🔐 INTERNAL_AUTH_SECRET (added)"
fi

chmod 600 .env

echo
echo "✅ .env written with generated secrets. It is gitignored — keep it that way."
echo "   Next: docker compose up -d"
