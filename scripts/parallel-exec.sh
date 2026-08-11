#!/bin/bash

# Parallel Execution Helper Script
# Executes commands in parallel with optional job limit
# Usage: ./scripts/parallel-exec.sh <command1> [command2] ... [--jobs N]

set -euo pipefail

# Default job limit
MAX_JOBS="${PARALLEL_JOBS:-$(nproc)}"

# Parse arguments
COMMANDS=()
JOBS_SPECIFIED=false

for arg in "$@"; do
    if [[ "$arg" == "--jobs" ]] || [[ "$arg" == "-j" ]]; then
        JOBS_SPECIFIED=true
        continue
    elif [ "$JOBS_SPECIFIED" = true ]; then
        MAX_JOBS="$arg"
        JOBS_SPECIFIED=false
        continue
    else
        COMMANDS+=("$arg")
    fi
done

if [ ${#COMMANDS[@]} -eq 0 ]; then
    echo "Usage: $0 <command1> [command2] ... [--jobs N]"
    echo "Example: $0 'make build-auth-service' 'make build-inventory-service' --jobs 4"
    exit 1
fi

# Execute commands in parallel with job limit
(
    for cmd in "${COMMANDS[@]}"; do
        # Wait if we've reached max jobs
        while [ $(jobs -r | wc -l) -ge "$MAX_JOBS" ]; do
            sleep 0.1
        done
        
        # Run command in background
        eval "$cmd" &
    done
    
    # Wait for all jobs to complete
    wait
)
