#!/bin/bash
#
# Tear down THIS deployment.
#
# Scope: containers, volumes and networks carrying this compose project's label,
# and — with --images — the images compose built for it. Nothing else on the
# Docker daemon is touched. If you are running this stack beside other
# containers, they survive.
#
# That is a deliberate rewrite. This script used to run `docker stop $(docker ps
# -q)`, `docker rm -f $(docker ps -aq)`, `docker network rm` over every custom
# network, remove every dangling volume — which, having just deleted every
# container, meant every volume on the host — and finish with `docker image
# prune -a -f`. On a developer's laptop with one stack that looks like it works.
# On any shared machine it deletes other people's work, and the name on the tin
# ("cleanup-docker --dev") gives no hint that it would.
#
# Usage:
#   ./scripts/cleanup-docker.sh [--dev|--prod|--ec2-smoke] [OPTIONS]
#
#   --dev / --prod / --ec2-smoke   pick the compose file (default: auto-detect)
#   --env FILE / --compose FILE    specify them explicitly
#   --images                       also remove images built for this project
#   --build-cache                  also prune the BuildKit cache (HOST-WIDE, prompts)
#   --clean-certs                  also remove config/certs/ (regenerated on next start)
#   --dry-run                      print what would be removed, remove nothing
#   --yes                          do not prompt (required for --build-cache non-interactively)
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# shellcheck source=lib/docker-scope.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/docker-scope.sh"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
err() { echo -e "${RED}$*${NC}"; }

log "🧹 Docker Cleanup"
log "================="

DCMD=$(detect_compose_cmd) || exit 1

ENV_FILE=""
COMPOSE_FILE=""
ENV_NAME=""
CLEAN_CERTS=false
CLEAN_IMAGES=false
CLEAN_BUILD_CACHE=false
DRY_RUN=false
export ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --env)         ENV_FILE="$2"; ENV_NAME="Custom"; shift 2 ;;
        --compose)     COMPOSE_FILE="$2"; ENV_NAME="${ENV_NAME:-Custom}"; shift 2 ;;
        --ec2-smoke)   ENV_FILE=".env.ec2-smoke"; COMPOSE_FILE="docker-compose.ec2-smoke.yml"; ENV_NAME="EC2-Smoke"; shift ;;
        --prod)        ENV_FILE=".env.prod";      COMPOSE_FILE="docker-compose.prod.yml";      ENV_NAME="Production"; shift ;;
        --dev)         ENV_FILE="";               COMPOSE_FILE="docker-compose.yml";           ENV_NAME="Development"; shift ;;
        --clean-certs) CLEAN_CERTS=true; shift ;;
        --images)      CLEAN_IMAGES=true; shift ;;
        --build-cache) CLEAN_BUILD_CACHE=true; shift ;;
        --dry-run)     DRY_RUN=true; shift ;;
        --yes|-y)      ASSUME_YES=1; shift ;;
        --help|-h)     sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             warn "Unknown option: $1 (see --help)"; shift ;;
    esac
done

# ─── Which deployment ───────────────────────────────────────────────────────

if [[ -z "$COMPOSE_FILE" ]]; then
    candidates=()
    [[ -f ".env.ec2-smoke" ]] && candidates+=("EC2-Smoke|.env.ec2-smoke|docker-compose.ec2-smoke.yml")
    [[ -f ".env.prod"      ]] && candidates+=("Production|.env.prod|docker-compose.prod.yml")
    [[ -f "docker-compose.yml" ]] && candidates+=("Development||docker-compose.yml")

    if [[ ${#candidates[@]} -eq 0 ]]; then
        err "No compose file found in $PROJECT_ROOT"
        exit 1
    elif [[ ${#candidates[@]} -eq 1 ]]; then
        IFS='|' read -r ENV_NAME ENV_FILE COMPOSE_FILE <<< "${candidates[0]}"
        log "Auto-detected environment: $ENV_NAME"
    else
        if [[ ! -t 0 ]]; then
            err "Several deployments present and this is not a terminal. Pass --dev, --prod or --ec2-smoke."
            exit 1
        fi
        warn "Multiple deployments detected. Which one?"
        for i in "${!candidates[@]}"; do
            IFS='|' read -r n _ c <<< "${candidates[$i]}"
            echo "  $((i + 1))) $n ($c)"
        done
        read -r -p "Select [1-${#candidates[@]}]: " choice
        [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#candidates[@]} )) || { err "Cancelled"; exit 1; }
        IFS='|' read -r ENV_NAME ENV_FILE COMPOSE_FILE <<< "${candidates[$((choice - 1))]}"
    fi
fi

[[ -f "$COMPOSE_FILE" ]] || { err "Compose file not found: $COMPOSE_FILE"; exit 1; }
if [[ -n "$ENV_FILE" && ! -f "$ENV_FILE" ]]; then
    err "Environment file not found: $ENV_FILE"
    exit 1
fi

PROJECT=$(compose_project_name "$PROJECT_ROOT" "$ENV_FILE")
assert_project_scope "$PROJECT" || exit 1

log "Environment:  ${ENV_NAME:-Custom}"
log "Compose file: $COMPOSE_FILE"
log "Env file:     ${ENV_FILE:-<none>}"
log "Project:      $PROJECT  ← everything below is filtered on this"

compose() {
    if [[ -n "$ENV_FILE" ]]; then
        $DCMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
    else
        $DCMD -f "$COMPOSE_FILE" "$@"
    fi
}

run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "    [dry-run] $*"
    else
        "$@" >/dev/null 2>&1 || true
    fi
}

# ─── 1. Compose teardown ────────────────────────────────────────────────────
#
# `down -v --remove-orphans` is the whole job in one call: it stops and removes
# this project's containers, its named volumes and its networks, and orphans
# left behind by services that have since been renamed or deleted. The sweeps
# below only exist to catch what a partial or interrupted run left behind.

log ""
log "🐳 docker compose down -v --remove-orphans"
if [[ "$DRY_RUN" == "true" ]]; then
    echo "    [dry-run] compose down -v --remove-orphans"
else
    compose down -v --remove-orphans 2>&1 | sed 's/^/    /' || warn "    compose down reported errors — sweeping leftovers below"
fi

# ─── 2. Scoped sweeps ───────────────────────────────────────────────────────

sweep() {
    local what="$1" lister="$2" remover="$3"
    local items
    items=$($lister "$PROJECT")
    if [[ -z "$items" ]]; then
        log "  ✅ no $what left"
        return
    fi
    log "  Removing $(echo "$items" | wc -l | tr -d ' ') $what:"
    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        echo "    - $item"
        run $remover "$item"
    done <<< "$items"
}

log ""
log "🔍 Sweeping anything left labelled $PROJECT..."
sweep "container(s)" project_containers "docker rm -f"
sweep "volume(s)"    project_volumes    "docker volume rm -f"
sweep "network(s)"   project_networks   "docker network rm"

# ─── 3. Optional: images built for this project ─────────────────────────────

if [[ "$CLEAN_IMAGES" == "true" ]]; then
    log ""
    log "🖼️  Removing images built for $PROJECT (pulled base images are left alone)..."
    sweep "image(s)" project_built_images "docker rmi -f"
fi

# ─── 4. Optional: BuildKit cache (host-wide — cannot be scoped) ──────────────

if [[ "$CLEAN_BUILD_CACHE" == "true" ]]; then
    log ""
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "    [dry-run] docker builder prune -af"
    elif require_confirmation "Pruning the BuildKit cache discards build cache for every project on this machine."; then
        docker builder prune -af >/dev/null 2>&1 || true
        ok "  ✅ build cache pruned"
    else
        log "  ⏭️  build cache left alone"
    fi
fi

# ─── 5. Optional: local mTLS certs ──────────────────────────────────────────

if [[ "$CLEAN_CERTS" == "true" ]]; then
    log ""
    log "🔐 Removing config/certs/ ..."
    if [[ -d "$PROJECT_ROOT/config/certs" ]]; then
        run rm -rf "$PROJECT_ROOT/config/certs"
        ok "  ✅ removed (regenerated on the next start-session.sh)"
    else
        log "  nothing at config/certs/"
    fi
fi

# ─── Report ─────────────────────────────────────────────────────────────────

log ""
if [[ "$DRY_RUN" == "true" ]]; then
    ok "✅ Dry run complete — nothing was removed."
else
    ok "✅ Cleanup complete for project '$PROJECT'."
fi
log ""
log "Still on this host (untouched by this script):"
log "  containers: $(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')   volumes: $(docker volume ls -q 2>/dev/null | wc -l | tr -d ' ')   images: $(docker images -q 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$CLEAN_IMAGES" != "true" ]]; then
    log ""
    log "Images built for this project were kept, so the next start is fast."
    log "Pass --images for a cold rebuild."
fi
