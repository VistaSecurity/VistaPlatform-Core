#!/usr/bin/env bash
# Single source of truth for the platform-admin credentials that
# scripts/database/seed.sql seeds.
#
# WHY THIS FILE EXISTS: these values used to be re-typed in every smoke and
# deploy script. When seed.sql moved to 'PlatformAdm!n2026' the copies stayed on
# the old 'Password123!', so prod-smoke.sh's admin login 401'd and four scripts
# printed instructions that could not work. Source this file instead of
# hardcoding; scripts/audit-seed-credentials.mjs fails the build if the value
# here drifts from the comment in seed.sql, and
# TestSeedAdminPasswordMatchesSeededHash (services/admin-service) proves it
# against the real Argon2id hashes.
#
# Usage:  source "$(dirname "$0")/lib/seed-credentials.sh"

# Emails seeded by scripts/database/seed.sql.
SEED_SUPER_ADMIN_EMAIL="su_admin@vistaplatform.invalid"
SEED_PLATFORM_ADMIN_EMAIL="admin@vistaplatform.invalid"

# The published default password for BOTH seeded admins above.
# Keep in lockstep with the "Default dev password:" comments in seed.sql.
SEED_ADMIN_PASSWORD='PlatformAdm!n2026'

# IMPORTANT: both seeded admins carry force_password_change = true.
# Logging in on SEED_ADMIN_PASSWORD returns a LIMITED, change-password-only
# access token — the shared auth middleware rejects every other endpoint with
# it. Anything that needs a working admin session must rotate the password
# first (see the rotate_seed_admin_password helper in prod-smoke.sh), not just
# log in. A non-empty access_token in the login response does NOT mean the
# session can do anything.
#
# The password a smoke run rotates TO. Overridable so a shared environment
# doesn't have to use the published value.
SMOKE_ADMIN_PASSWORD="${SMOKE_ADMIN_PASSWORD:-VtSmoke2026!}"

# Passwords seeded by other scripts, for reference in printed instructions:
#   scripts/database/seed_demo.sql          demo tenant users  -> Password123!
#   scripts/seed-smoke-platform-admins.sh   pa_admin/st_admin  -> p@ssword1!
