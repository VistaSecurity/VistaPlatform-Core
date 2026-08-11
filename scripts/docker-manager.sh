#!/bin/bash

# Docker Compose Management Script
# Provides safe start/stop/restart operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get absolute path to project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=lib/docker-scope.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/docker-scope.sh"

# Every container/volume/network operation below filters on this label. The
# earlier version of this script listed `docker ps -aq` and offered to remove
# the result, which on a machine running anything else meant offering to delete
# containers that had nothing to do with this project — under the heading
# "orphaned containers".
PROJECT="$(compose_project_name "$PROJECT_ROOT")"
assert_project_scope "$PROJECT" || exit 1

# Function to check if docker compose is available
check_docker_compose() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
        return 0
    elif command -v docker-compose &> /dev/null; then
        echo "docker-compose"
        return 0
    else
        print_error "Neither 'docker compose' nor 'docker-compose' found"
        exit 1
    fi
}

# Function to check for stopped containers left over from this project
check_orphans() {
    print_status "Checking for leftover $PROJECT containers..."

    # Stopped-only, and only ours: a running container is either part of the
    # stack we are about to start (compose will reuse it) or somebody else's.
    stale=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "status=exited" --filter "status=created" 2>/dev/null || true)
    if [ -n "$stale" ]; then
        print_warning "Found stopped containers from a previous run:"
        docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}"
        echo ""
        read -p "Remove them? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "$stale" | xargs -r docker rm -f 2>/dev/null || true
            print_success "Leftover containers removed"
        fi
    else
        print_success "No leftover containers found"
    fi
}

# Function to start services
start_services() {
    print_status "Starting services..."
    
    COMPOSE_CMD=$(check_docker_compose)
    
    # Check for orphans first
    check_orphans
    
    # Start services from project root
    cd "$PROJECT_ROOT"
    $COMPOSE_CMD up -d
    
    print_success "Services started successfully"
    
    # Show status
    print_status "Service status:"
    $COMPOSE_CMD ps
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."
    
    COMPOSE_CMD=$(check_docker_compose)
    
    # Stop compose services from project root
    cd "$PROJECT_ROOT"
    $COMPOSE_CMD down
    
    # Check for containers of THIS project that survived compose down
    remaining_containers=$(project_containers "$PROJECT")
    if [ -n "$remaining_containers" ]; then
        print_warning "Some $PROJECT containers survived 'compose down':"
        docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}"
        echo ""
        read -p "Force stop and remove them? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Force removing..."
            echo "$remaining_containers" | xargs -r docker rm -f 2>/dev/null || true
            print_success "All $PROJECT containers removed"
        fi
    else
        print_success "All services stopped successfully"
    fi
}

# Function to restart services
restart_services() {
    print_status "Restarting services..."
    stop_services
    sleep 2
    start_services
}

# Function to show service status
show_status() {
    print_status "Service status:"
    
    COMPOSE_CMD=$(check_docker_compose)
    cd "$PROJECT_ROOT"
    $COMPOSE_CMD ps
    
    echo ""
    print_status "All containers:"
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

# Function to show logs
show_logs() {
    local service=${1:-""}
    
    if [ -n "$service" ]; then
        print_status "Showing logs for $service..."
        docker logs -f "crypto-$service"
    else
        print_status "Showing logs for all services..."
        COMPOSE_CMD=$(check_docker_compose)
        cd "$PROJECT_ROOT"
        $COMPOSE_CMD logs -f
    fi
}

# Function to remove this project's containers, networks and volumes
#
# `docker network prune`, `docker volume prune` and `docker image prune` are all
# host-wide and were called here unfiltered, so "clean-all" emptied the daemon
# rather than the deployment. Scoped to the project label, the same command is
# useful and survivable.
cleanup_all() {
    print_warning "This removes all containers, networks and volumes for project '$PROJECT'."
    print_warning "Other projects on this machine are not affected."
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Cleaning up $PROJECT..."

        cd "$PROJECT_ROOT"
        $(check_docker_compose) down -v --remove-orphans 2>/dev/null || true

        project_containers "$PROJECT" | xargs -r docker rm -f 2>/dev/null || true
        project_volumes    "$PROJECT" | xargs -r docker volume rm -f 2>/dev/null || true
        project_networks   "$PROJECT" | xargs -r docker network rm 2>/dev/null || true

        print_success "Cleanup of '$PROJECT' finished"
        print_status "To remove its built images too: ./scripts/cleanup-docker.sh --dev --images"
    else
        print_status "Cleanup cancelled"
    fi
}

# Function to show help
show_help() {
    echo "Docker Compose Management Script"
    echo "================================"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start           Start all services"
    echo "  stop            Stop all services"
    echo "  restart         Restart all services"
    echo "  status      Show service status"
    echo "  logs [service]  Show logs (optionally for specific service)"
    echo "  cleanup         Remove leftover stopped containers from this project"
    echo "  clean-all       Remove this project's containers, networks and volumes"
    echo "                  (scoped to compose project '$PROJECT' — other stacks untouched)"
    echo "  prod-start      Start services with production compose file"
    echo "  prod-stop       Stop services started with production compose file"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 stop"
    echo "  $0 logs inventory-service"
    echo "  $0 cleanup"
}

# Main execution
main() {
    case "${1:-help}" in
        start)
            start_services
            ;;
        prod-start)
            COMPOSE_CMD=$(check_docker_compose)
            cd "$PROJECT_ROOT"
            $COMPOSE_CMD -f docker-compose.prod.yml up -d
            ;;
        stop)
            stop_services
            ;;
        prod-stop)
            COMPOSE_CMD=$(check_docker_compose)
            cd "$PROJECT_ROOT"
            $COMPOSE_CMD -f docker-compose.prod.yml down
            ;;
        restart)
            restart_services
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "$2"
            ;;
        cleanup)
            check_orphans
            ;;
        clean-all)
            cleanup_all
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
