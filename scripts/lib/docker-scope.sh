#!/bin/bash
# Project-scoped Docker helpers.
#
# Every teardown script in this repository used to reach for `docker ps -aq`,
# `docker volume prune` or `docker image prune -a`. Those are HOST-wide: they do
# not know what a compose project is, and on any machine that runs more than one
# stack they delete other people's containers, volumes and images. A user who
# runs a script called "cleanup-docker.sh --dev" is asking to remove THIS
# deployment, not to empty their Docker installation.
#
# Compose labels everything it creates with com.docker.compose.project=<name>.
# That label is the scope. Every helper here filters on it, so a script built
# from these functions cannot touch a resource this project did not create.
#
# Source it:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/docker-scope.sh"
#
# The one thing genuinely impossible to scope is the BuildKit cache
# (`docker builder prune`), which is shared across every project on the daemon.
# Scripts must not call it silently — see require_confirmation().

# ─── Compose command ────────────────────────────────────────────────────────

detect_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        echo "Neither 'docker compose' nor 'docker-compose' found" >&2
        return 1
    fi
}

# ─── Project name ───────────────────────────────────────────────────────────

# Read COMPOSE_PROJECT_NAME from a Compose env file without executing it.
compose_project_name_from_env_file() {
    local file="$1" line value
    [[ -f "$file" ]] || return 1

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == export[[:space:]]* ]] && line="${line#export }"
        [[ "$line" =~ ^COMPOSE_PROJECT_NAME[[:space:]]*= ]] || continue

        value="${line#*=}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi
        [[ -n "$value" ]] || return 1
        echo "$value"
        return 0
    done < "$file"

    return 1
}

# Resolve the compose project name for a directory.
#
# Asking Docker beats guessing: if any container from this project still exists,
# its own label is the authoritative answer, whatever the directory is called and
# whatever COMPOSE_PROJECT_NAME was set to when it was created. Only when nothing
# exists do we fall back to compose's own derivation (COMPOSE_PROJECT_NAME from
# the shell, explicit --env-file, default .env, else the lowercased basename with
# separators stripped).
compose_project_name() {
    local root="${1:-$PWD}" env_file="${2:-}" name=""

    if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
        echo "$COMPOSE_PROJECT_NAME"
        return 0
    fi

    if [[ -n "$env_file" ]]; then
        local resolved_env_file="$env_file"
        [[ "$resolved_env_file" = /* ]] || resolved_env_file="$root/$resolved_env_file"
        if name=$(compose_project_name_from_env_file "$resolved_env_file"); then
            echo "$name"
            return 0
        fi
    fi

    if name=$(compose_project_name_from_env_file "$root/.env"); then
        echo "$name"
        return 0
    fi

    local guess
    guess=$(basename "$root" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_-')

    # Confirm against a live container if one is there.
    local cid
    cid=$(docker ps -aq --filter "label=com.docker.compose.project=$guess" 2>/dev/null | head -1 || true)
    if [[ -n "$cid" ]]; then
        name=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null || true)
    fi

    echo "${name:-$guess}"
}

# ─── Scoped listings ────────────────────────────────────────────────────────
#
# Each prints one id/name per line, empty if nothing matches. All four filter on
# the compose project label, so none of them can return a resource belonging to
# another stack.

project_containers() {
    docker ps -aq --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

project_volumes() {
    docker volume ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

project_networks() {
    docker network ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

# Images compose BUILT for this project. Compose does not label built images, so
# this matches the naming convention it uses (<project>-<service>) and nothing
# else. Pulled third-party images (postgres, redis, grafana …) are deliberately
# excluded: they are shared infrastructure, cheap to keep and expensive to
# re-pull, and they may well be in use by another stack on the same host.
project_built_images() {
    docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
        | awk -v prefix="$1-" 'index($0, prefix) == 1 { print }' || true
}

# ─── Safety rails ───────────────────────────────────────────────────────────

# Refuse to proceed with an empty or absurd project name. Without this, a caller
# whose name resolution failed would build the filter
# "label=com.docker.compose.project=" — which matches every compose-managed
# container on the host, i.e. exactly the bug this file exists to prevent.
assert_project_scope() {
    local name="$1"
    if [[ -z "$name" || "$name" == "/" || "$name" == "." ]]; then
        echo "❌ Could not determine the compose project name; refusing to run an unscoped cleanup." >&2
        return 1
    fi
    return 0
}

# Prompt before a genuinely host-wide operation. Honours --yes via ASSUME_YES=1
# and refuses (rather than assumes) when stdin is not a terminal, so a CI job or
# a piped run never silently wipes a shared daemon.
require_confirmation() {
    local what="$1"
    if [[ "${ASSUME_YES:-0}" == "1" ]]; then
        return 0
    fi
    if [[ ! -t 0 ]]; then
        echo "⏭️  Skipping host-wide step ($what) — not a terminal. Pass --yes to allow it." >&2
        return 1
    fi
    local reply
    read -r -p "⚠️  $what This affects the whole Docker daemon, not just this project. Continue? (y/N): " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}
