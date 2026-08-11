#!/bin/bash
# Database Validation Library
# Shared functions for database table/column checks, migration application, and seed validation
# Used by session-init.sh, deploy-ec2-smoke.sh, and other deployment scripts

# Default database connection parameters (can be overridden)
DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-crypto_inventory}"
DB_USER="${DB_USER:-crypto_user}"
DB_PASSWORD="${DB_PASSWORD:-crypto_pass_dev}"

# Docker compose command (can be overridden)
DCMD="${DCMD:-docker compose}"

# Colors for output (can be overridden by calling script)
BLUE="${BLUE:-\033[0;34m}"
GREEN="${GREEN:-\033[0;32m}"
YELLOW="${YELLOW:-\033[1;33m}"
RED="${RED:-\033[0;31m}"
NC="${NC:-\033[0m}"

# Logging functions (can be overridden by calling script)
log() { echo -e "${BLUE}$1${NC}"; }
ok() { echo -e "${GREEN}✅${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC} $1"; }
err() { echo -e "${RED}❌${NC} $1"; }

# Critical tables for service operation
# Format: "table_name:service_name:description"
get_critical_tables() {
    cat << 'EOF'
measurement_types:compliance-engine:Measurement types catalog
measurement_templates:compliance-engine:Measurement templates
platform_frameworks:compliance-engine:Compliance frameworks
platform_framework_controls:compliance-engine:Framework controls
control_measurements:compliance-engine:Control measurements
rule_vulnerability_mappings:compliance-engine:Rule-to-finding mappings
platform_roles:auth-service:Platform RBAC roles
tenant_roles:auth-service:Tenant RBAC roles
sso_providers:auth-service:SSO provider configurations
subscription_tiers:auth-service:Subscription tier definitions
tenant_usage:auth-service:Tenant usage tracking
user_workflow_progress:auth-service:Onboarding workflow progress
platform_integrations:admin-service:Platform integration configurations
platform_settings:admin-service:Platform-wide configuration settings
tenant_geographic_data:admin-service:Tenant geographic location data for dashboard
health_benchmarks:tenant-health-service:Health scoring benchmarks
device_jobs:device-interrogation-service:Device interrogation job tracking
platform_metrics_snapshots:monitoring-service:Platform metrics aggregation storage
service_health_events:monitoring-service:Service health event tracking
monitoring_alert_thresholds:monitoring-service:Alert threshold configurations
EOF
}

# Critical columns that must exist
# Format: "table_name.column_name:description"
get_critical_columns() {
    cat << 'EOF'
platform_frameworks.is_platform_default:Compliance framework default flag
EOF
}

# Migration dependency map
# Format: "migration_file:required_tables:description"
get_migration_dependencies() {
    cat << 'EOF'
27-compliance-framework-management.sql:measurement_types,platform_frameworks:Compliance framework schema
28-measurement-templates.sql:measurement_templates:Measurement templates
30-enhance-measurement-types.sql:measurement_types:Enhanced measurement types
EOF
}

# Get container name from service name
# Usage: get_container_name "postgres" -> "crypto-postgres"
get_container_name() {
    local service_name="$1"
    # Try docker compose ps first (works with service names)
    if command -v docker >/dev/null 2>&1; then
        # Try to get container name from docker compose
        local container=$(docker compose ps --format json 2>/dev/null | grep -o "\"Name\":\"crypto-$service_name\"" | cut -d'"' -f4 2>/dev/null || echo "")
        if [ -n "$container" ]; then
            echo "$container"
            return 0
        fi
        # Fallback: try direct docker ps
        container=$(docker ps --format "{{.Names}}" | grep -E "^crypto-$service_name$" | head -1)
        if [ -n "$container" ]; then
            echo "$container"
            return 0
        fi
        # Last resort: return service name (might work with docker compose exec)
        echo "$service_name"
    else
        echo "$service_name"
    fi
}

# Check if PostgreSQL is ready
check_postgres_ready() {
    local service_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"

    if command -v docker >/dev/null 2>&1; then
        # Try docker compose exec first (works with service names)
        if docker compose exec -T "$service_name" pg_isready -U "$db_user" -d "$db_name" >/dev/null 2>&1; then
            return 0
        fi
        # Fallback: try with container name
        local container_name=$(get_container_name "$service_name")
        if docker exec -T "$container_name" pg_isready -U "$db_user" -d "$db_name" >/dev/null 2>&1; then
            return 0
        fi
        return 1
    else
        return 1
    fi
}

# Execute SQL query and return result
# Usage: execute_sql "SELECT 1" [service_name] [db_user] [db_name]
execute_sql() {
    local query="$1"
    local service_name="${2:-postgres}"
    local db_user="${3:-$DB_USER}"
    local db_name="${4:-$DB_NAME}"

    if command -v docker >/dev/null 2>&1; then
        # Try docker compose exec first (works with service names)
        if docker compose exec -T "$service_name" psql -U "$db_user" -d "$db_name" -t -c "$query" 2>&1; then
            return 0
        fi
        # Fallback: try with container name
        local container_name=$(get_container_name "$service_name")
        docker exec -T "$container_name" psql -U "$db_user" -d "$db_name" -t -c "$query" 2>&1
    else
        echo ""
        return 1
    fi
}

# Check if table exists
# Returns: 0 if exists, 1 if not
check_table_exists() {
    local table_name="$1"
    local service_name="${2:-postgres}"
    local db_user="${3:-$DB_USER}"
    local db_name="${4:-$DB_NAME}"

    local result=$(execute_sql "
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = '$table_name'
        );
    " "$service_name" "$db_user" "$db_name")

    # Extract 't' or 'f' from result
    local exists=$(echo "$result" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")

    if [ "$exists" = "t" ]; then
        return 0
    else
        return 1
    fi
}

# Check if column exists in table
# Returns: 0 if exists, 1 if not
check_column_exists() {
    local table_name="$1"
    local column_name="$2"
    local service_name="${3:-postgres}"
    local db_user="${4:-$DB_USER}"
    local db_name="${5:-$DB_NAME}"

    local result=$(execute_sql "
        SELECT EXISTS (
            SELECT FROM information_schema.columns
            WHERE table_schema = 'public'
            AND table_name = '$table_name'
            AND column_name = '$column_name'
        );
    " "$service_name" "$db_user" "$db_name")

    # Extract 't' or 'f' from result
    local exists=$(echo "$result" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")

    if [ "$exists" = "t" ]; then
        return 0
    else
        return 1
    fi
}

# Apply migration file if required tables are missing
# Usage: apply_migration_if_needed "migration_file.sql" "table1,table2" [container_name] [db_user] [db_name]
apply_migration_if_needed() {
    local migration_file="$1"
    local required_tables="$2"
    local container_name="${3:-postgres}"
    local db_user="${4:-$DB_USER}"
    local db_name="${5:-$DB_NAME}"
    local migration_path="${6:-scripts/database}"

    # Check if any required table is missing
    local needs_migration=false
    IFS=',' read -ra TABLES <<< "$required_tables"
    for table in "${TABLES[@]}"; do
        table=$(echo "$table" | tr -d ' ')
        if ! check_table_exists "$table" "$container_name" "$db_user" "$db_name"; then
            needs_migration=true
            break
        fi
    done

    if [ "$needs_migration" = false ]; then
        return 0
    fi

    # Check if migration file exists
    local full_path="$migration_path/$migration_file"
    if [ ! -f "$full_path" ]; then
        warn "Migration file not found: $full_path"
        return 1
    fi

    log "Applying migration: $migration_file"

    # Apply migration
    local result=$(docker exec -i "$container_name" psql -U "$db_user" -d "$db_name" < "$full_path" 2>&1)

    # Check for errors (ignore "already exists" errors as they're expected for idempotent migrations)
    if echo "$result" | grep -qiE "error.*(already exists|duplicate key|already present)"; then
        log "Migration applied (some objects already existed - this is expected)"
        return 0
    elif echo "$result" | grep -qi "error"; then
        err "Migration failed: $migration_file"
        echo "$result" | grep -i "error" | head -5
        return 1
    else
        ok "Migration applied successfully: $migration_file"
        return 0
    fi
}

# Validate and apply migrations in dependency order
# Usage: apply_migrations_in_order [container_name] [db_user] [db_name] [migration_path]
apply_migrations_in_order() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"
    local migration_path="${4:-scripts/database}"

    local applied_any=false

    # Get migration dependencies
    while IFS=':' read -r migration_file required_tables description; do
        if [ -z "$migration_file" ]; then
            continue
        fi

        # Check if migration is needed
        if apply_migration_if_needed "$migration_file" "$required_tables" "$container_name" "$db_user" "$db_name" "$migration_path"; then
            applied_any=true
        fi
    done <<< "$(get_migration_dependencies)"

    if [ "$applied_any" = true ]; then
        # Wait a moment for changes to settle
        sleep 1
    fi

    return 0
}

# Validate seed script dependencies
# Checks that all tables/columns referenced in seed script exist
# Usage: validate_seed_dependencies "seed_file.sql" [container_name] [db_user] [db_name]
validate_seed_dependencies() {
    local seed_file="$1"
    local container_name="${2:-postgres}"
    local db_user="${3:-$DB_USER}"
    local db_name="${4:-$DB_NAME}"
    local seed_path="${5:-scripts/database}"

    local full_path="$seed_path/$seed_file"
    if [ ! -f "$full_path" ]; then
        warn "Seed file not found: $full_path"
        return 1
    fi

    local missing_deps=()

    # Extract table references from seed file (FROM, INTO, REFERENCES, JOIN)
    # Use [a-z0-9_]+ so full identifiers (e.g. control_cc661_id, iso27001_framework_id) are captured
    local tables=$(grep -oE "(FROM|INTO|REFERENCES|JOIN)\s+[a-z0-9_]+" "$full_path" | \
        sed -E 's/(FROM|INTO|REFERENCES|JOIN)\s+//' | \
        sort -u | \
        grep -vE "^(SELECT|INSERT|UPDATE|DELETE|VALUES|WHERE|ON|AND|OR|NOT|EXISTS|CASE|WHEN|THEN|ELSE|END|DO|DECLARE|BEGIN|RETURN|IF|LOOP|FOR|IN)$")

    # Known PL/pgSQL variable names (INTO targets) that the table regex captures but are not tables
    local skip_table_patterns=(
        "algorithm_count" "best_practices_framework_id" "platform_user_count" "platform_role_count"
        "platform_admin_id" "tls_version_mt_id" "cert_expiration_mt_id" "key_size_mt_id"
        "pfs_support_mt_id" "hash_algorithm_mt_id" "key_exchange_mt_id" "symmetric_encryption_mt_id"
        "cert_chain_valid_mt_id" "soc2_framework_id" "pci_dss_framework_id" "iso27001_framework_id"
        "nist_framework_id" "framework_count"
        "admin_user_id" "super_admin_role_id" "permission_count" "tenant_record" "tenant_role_id"
        "license_count" "default_count" "total_tenants" "licenses_created" "licenses_existing" "defaults_set"
    )

    # Check each table exists
    for table in $tables; do
        # Skip common SQL keywords and function names
        if [[ "$table" =~ ^(uuid|now|gen_random_uuid|count|sum|max|min|avg|coalesce|null|true|false)$ ]]; then
            continue
        fi
        # Skip schema names (not app tables)
        if [[ "$table" == "information_schema" ]]; then
            continue
        fi
        # Skip known PL/pgSQL INTO targets (variable names, not tables)
        local skip=0
        for p in "${skip_table_patterns[@]}"; do
            if [[ "$table" == "$p" ]]; then skip=1; break; fi
        done
        [[ $skip -eq 1 ]] && continue
        if [[ "$table" =~ ^control_.*_id$ ]]; then
            continue
        fi

        if ! check_table_exists "$table" "$container_name" "$db_user" "$db_name"; then
            missing_deps+=("table:$table")
        fi
    done

    # Extract column references (table.column pattern)
    local columns=$(grep -oE "[a-z_]+\\.[a-z_]+" "$full_path" | \
        sort -u | \
        grep -vE "^(information_schema|pg_|public\\.)" | \
        sed 's/^public\.//')

    # False positives: refs that appear in RAISE WARNING message text (measurement codes, not column names)
    local skip_column_refs=(
        "measurement_types.cert_expiration_days"
        "measurement_types.tls_version"
        "measurement_types.key_size"
        "measurement_types.symmetric_encryption"
    )

    # Check each column exists
    for col_ref in $columns; do
        local skip_col=0
        for skip_ref in "${skip_column_refs[@]}"; do
            if [[ "$col_ref" == "$skip_ref" ]]; then skip_col=1; break; fi
        done
        [[ $skip_col -eq 1 ]] && continue
        IFS='.' read -r table_name column_name <<< "$col_ref"
        if [ -n "$table_name" ] && [ -n "$column_name" ]; then
            if check_table_exists "$table_name" "$container_name" "$db_user" "$db_name"; then
                if ! check_column_exists "$table_name" "$column_name" "$container_name" "$db_user" "$db_name"; then
                    missing_deps+=("column:$table_name.$column_name")
                fi
            fi
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        warn "Seed script $seed_file has missing dependencies:"
        for dep in "${missing_deps[@]}"; do
            warn "  - $dep"
        done

        # Attempt to auto-fix by applying migrations
        log "Attempting to auto-fix by applying migrations..."
        if apply_migrations_in_order "$container_name" "$db_user" "$db_name" "$seed_path"; then
            # Re-check dependencies
            local still_missing=()
            for dep in "${missing_deps[@]}"; do
                IFS=':' read -r dep_type dep_name <<< "$dep"
                if [ "$dep_type" = "table" ]; then
                    if ! check_table_exists "$dep_name" "$container_name" "$db_user" "$db_name"; then
                        still_missing+=("$dep")
                    fi
                elif [ "$dep_type" = "column" ]; then
                    IFS='.' read -r table_name column_name <<< "$dep_name"
                    if ! check_column_exists "$table_name" "$column_name" "$container_name" "$db_user" "$db_name"; then
                        still_missing+=("$dep")
                    fi
                fi
            done

            if [ ${#still_missing[@]} -gt 0 ]; then
                err "Could not auto-fix all dependencies for $seed_file"
                return 1
            else
                ok "All dependencies resolved for $seed_file"
                return 0
            fi
        else
            err "Failed to auto-fix dependencies for $seed_file"
            return 1
        fi
    fi

    return 0
}

# Check all critical tables and columns
# Returns: 0 if all exist, 1 if any missing
# Usage: check_critical_tables_and_columns [container_name] [db_user] [db_name]
check_critical_tables_and_columns() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"

    local missing_tables=()
    local missing_columns=()
    local all_ok=true

    # Check critical tables
    while IFS=':' read -r table_name service_name description; do
        if [ -z "$table_name" ]; then
            continue
        fi

        if ! check_table_exists "$table_name" "$container_name" "$db_user" "$db_name"; then
            missing_tables+=("$table_name:$service_name:$description")
            all_ok=false
        fi
    done <<< "$(get_critical_tables)"

    # Check critical columns
    while IFS=':' read -r column_ref description; do
        if [ -z "$column_ref" ]; then
            continue
        fi

        IFS='.' read -r table_name column_name <<< "$column_ref"
        if [ -n "$table_name" ] && [ -n "$column_name" ]; then
            if ! check_column_exists "$table_name" "$column_name" "$container_name" "$db_user" "$db_name"; then
                missing_columns+=("$column_ref:$description")
                all_ok=false
            fi
        fi
    done <<< "$(get_critical_columns)"

    # Return results via global variables (bash limitation)
    CRITICAL_MISSING_TABLES=("${missing_tables[@]}")
    CRITICAL_MISSING_COLUMNS=("${missing_columns[@]}")

    if [ "$all_ok" = true ]; then
        return 0
    else
        return 1
    fi
}

# Detect if database is fresh (empty) or existing (has data)
# Returns: 0 if fresh, 1 if existing
# Usage: is_database_fresh [container_name] [db_user] [db_name]
# This function checks PostgreSQL logs to determine if the database was freshly initialized
# or if it detected existing data and skipped initialization
is_database_fresh() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"

    # First, check PostgreSQL logs for the definitive answer
    # PostgreSQL logs will show either:
    # 1. "initdb: ..." messages (fresh database - initdb ran)
    # 2. "PostgreSQL Database directory appears to contain a database; Skipping initialization" (existing database)
    # CRITICAL: Check MOST RECENT logs first (tail) to get the current container state
    local actual_container=$(get_container_name "$container_name")
    if [ -n "$actual_container" ]; then
        # Check the BEGINNING of the logs for this container start
        # The first messages tell us if this was a fresh init or existing database
        local early_logs=$(docker logs "$actual_container" 2>&1 | head -50)

        # Check if initdb ran at the start (fresh database)
        # Look for the initdb initialization sequence at the beginning
        local initdb_sequence=$(echo "$early_logs" | grep -E "(The files belonging to this database|initdb:|creating subdirectories|running bootstrap script)" | head -3)
        if [ -n "$initdb_sequence" ]; then
            # Found initdb sequence at the start, so this is a fresh database
            return 0  # Fresh database
        fi

        # Check if PostgreSQL skipped initialization at the start (existing database)
        # Look for skip message in early logs
        local skip_init_log=$(echo "$early_logs" | grep -E "PostgreSQL Database directory appears to contain.*Skipping initialization" | head -1)
        if [ -n "$skip_init_log" ]; then
            # PostgreSQL explicitly said it found existing data and skipped initialization
            return 1  # Existing database
        fi

        # Fallback: Check most recent logs if early logs don't have clear indicators
        # This handles cases where container was restarted after initialization
        local recent_logs=$(docker logs "$actual_container" 2>&1 | tail -100)
        local recent_initdb=$(echo "$recent_logs" | grep -E "^initdb:" | tail -1)
        if [ -n "$recent_initdb" ]; then
            # Found recent initdb, likely a fresh database
            return 0  # Fresh database
        fi
    fi

    # Fallback: If we can't check logs, use table count as before
    # But this is less reliable because a fresh database will have tables after init
    local table_count=$(execute_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")

    if [ "$table_count" = "0" ] || [ -z "$table_count" ]; then
        return 0  # Fresh database (no tables yet)
    else
        # Tables exist - could be fresh (after init) or existing
        # Without log access, we can't be sure, so assume existing to be safe
        return 1  # Existing database (or fresh but already initialized)
    fi
}

# Verify seed data was inserted
# Checks for minimum expected counts in critical tables
# Usage: verify_seed_data [container_name] [db_user] [db_name]
verify_seed_data() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"

    local all_ok=true
    local missing_data=()

    # Check platform_users has at least 1 admin user
    if check_table_exists "platform_users" "$container_name" "$db_user" "$db_name"; then
        local user_count=$(execute_sql "SELECT COUNT(*) FROM platform_users;" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")
        if [ "$user_count" = "0" ] || [ -z "$user_count" ]; then
            missing_data+=("platform_users:expected at least 1 admin user, found 0")
            all_ok=false
        fi
    fi

    # Check platform_roles has roles
    if check_table_exists "platform_roles" "$container_name" "$db_user" "$db_name"; then
        local role_count=$(execute_sql "SELECT COUNT(*) FROM platform_roles;" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")
        if [ "$role_count" = "0" ] || [ -z "$role_count" ]; then
            missing_data+=("platform_roles:expected at least 1 role, found 0")
            all_ok=false
        fi
    fi

    # Check measurement_types has types (if table exists)
    if check_table_exists "measurement_types" "$container_name" "$db_user" "$db_name"; then
        local type_count=$(execute_sql "SELECT COUNT(*) FROM measurement_types;" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")
        if [ "$type_count" = "0" ] || [ -z "$type_count" ]; then
            missing_data+=("measurement_types:expected at least 1 type, found 0")
            all_ok=false
        fi
    fi

    # Check platform_frameworks has frameworks (if table exists)
    if check_table_exists "platform_frameworks" "$container_name" "$db_user" "$db_name"; then
        local framework_count=$(execute_sql "SELECT COUNT(*) FROM platform_frameworks;" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")
        if [ "$framework_count" = "0" ] || [ -z "$framework_count" ]; then
            missing_data+=("platform_frameworks:expected at least 1 framework, found 0")
            all_ok=false
        fi
    fi

    # Return results via global variable
    SEED_DATA_MISSING=("${missing_data[@]}")

    if [ "$all_ok" = true ]; then
        return 0
    else
        return 1
    fi
}

# Validate that required measurement_types codes exist
# This is critical for framework seeding to work
# Usage: validate_measurement_types_data [container_name] [db_user] [db_name]
validate_measurement_types_data() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"

    # Required measurement type codes for framework seeding
    local required_codes=(
        "tls_version"
        "cert_expiration_days"
        "key_size"
        "pfs_support"
        "hash_algorithm"
        "key_exchange_algorithm"
        "symmetric_encryption"
        "certificate_chain_valid"
    )

    local missing_codes=()

    # First check if table exists
    if ! check_table_exists "measurement_types" "$container_name" "$db_user" "$db_name"; then
        warn "measurement_types table does not exist"
        return 1
    fi

    # Check each required code
    for code in "${required_codes[@]}"; do
        local count=$(execute_sql "SELECT COUNT(*) FROM measurement_types WHERE code = '$code';" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")
        if [ "$count" = "0" ] || [ -z "$count" ]; then
            missing_codes+=("$code")
        fi
    done

    if [ ${#missing_codes[@]} -gt 0 ]; then
        warn "Missing required measurement_types codes: ${missing_codes[*]}"
        warn "Framework seeding will fail silently without these codes"
        return 1
    fi

    return 0
}

# Comprehensive database initialization validation
# Checks schema, critical tables/columns, and seed data
# Usage: validate_database_initialization [container_name] [db_user] [db_name] [timeout_seconds]
validate_database_initialization() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"
    local timeout="${4:-120}"

    local start_time=$(date +%s)
    local elapsed=0
    local check_interval=2
    local last_progress=0

    log "Validating database initialization (timeout: ${timeout}s)..."

    while [ $elapsed -lt $timeout ]; do
        # Check if Postgres is ready
        if ! check_postgres_ready "$container_name" "$db_user" "$db_name"; then
            if [ $((elapsed - last_progress)) -ge 10 ]; then
                log "   Waiting for PostgreSQL to be ready... (${elapsed}s)"
                last_progress=$elapsed
            fi
            sleep $check_interval
            elapsed=$(($(date +%s) - start_time))
            continue
        fi

        # Check critical tables and columns
        if ! check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
            if [ $((elapsed - last_progress)) -ge 10 ]; then
                log "   Waiting for schema to be applied... (${elapsed}s)"
                if [ ${#CRITICAL_MISSING_TABLES[@]} -gt 0 ]; then
                    log "   Missing tables: ${CRITICAL_MISSING_TABLES[*]}"
                fi
                if [ ${#CRITICAL_MISSING_COLUMNS[@]} -gt 0 ]; then
                    log "   Missing columns: ${CRITICAL_MISSING_COLUMNS[*]}"
                fi
                last_progress=$elapsed
            fi
            sleep $check_interval
            elapsed=$(($(date +%s) - start_time))
            continue
        fi

        # Check seed data (non-blocking - tables are more critical)
        # Only wait for seed data if we've been waiting less than half the timeout
        # This allows schema to complete even if seed data takes longer
        if [ $elapsed -lt $((timeout / 2)) ]; then
            if ! verify_seed_data "$container_name" "$db_user" "$db_name"; then
                if [ $((elapsed - last_progress)) -ge 10 ]; then
                    log "   Waiting for seed data to be loaded... (${elapsed}s)"
                    if [ ${#SEED_DATA_MISSING[@]} -gt 0 ]; then
                        log "   Missing data: ${SEED_DATA_MISSING[*]}"
                    fi
                    last_progress=$elapsed
                fi
                sleep $check_interval
                elapsed=$(($(date +%s) - start_time))
                continue
            fi
        else
            # After half timeout, seed data is optional - just log if missing
            if ! verify_seed_data "$container_name" "$db_user" "$db_name"; then
                if [ ${#SEED_DATA_MISSING[@]} -gt 0 ]; then
                    warn "   Seed data still missing (non-blocking): ${SEED_DATA_MISSING[*]}"
                fi
            fi
        fi

        # All checks passed
        ok "Database initialization complete (took ${elapsed}s)"
        return 0
    done

    # Timeout reached
    err "Database initialization validation timed out after ${timeout}s"

    # Provide diagnostic information
    log "Current database state:"
    local table_count=$(execute_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';" "$container_name" "$db_user" "$db_name" | tr -d ' ' || echo "0")
    log "   Tables found: $table_count"

    if ! check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
        if [ ${#CRITICAL_MISSING_TABLES[@]} -gt 0 ]; then
            err "   Missing critical tables:"
            for table_info in "${CRITICAL_MISSING_TABLES[@]}"; do
                IFS=':' read -r table_name service_name description <<< "$table_info"
                err "     - $table_name ($service_name): $description"
            done
        fi
        if [ ${#CRITICAL_MISSING_COLUMNS[@]} -gt 0 ]; then
            err "   Missing critical columns:"
            for col_info in "${CRITICAL_MISSING_COLUMNS[@]}"; do
                IFS=':' read -r column_ref description <<< "$col_info"
                err "     - $column_ref: $description"
            done
        fi
    fi

    if ! verify_seed_data "$container_name" "$db_user" "$db_name"; then
        if [ ${#SEED_DATA_MISSING[@]} -gt 0 ]; then
            err "   Missing seed data:"
            for data_info in "${SEED_DATA_MISSING[@]}"; do
                IFS=':' read -r table_name issue <<< "$data_info"
                err "     - $table_name: $issue"
            done
        fi
    fi

    return 1
}

# Apply schema.sql if critical tables/columns are missing
# Usage: apply_schema_if_needed [container_name] [db_user] [db_name] [schema_path]
apply_schema_if_needed() {
    local container_name="${1:-postgres}"
    local db_user="${2:-$DB_USER}"
    local db_name="${3:-$DB_NAME}"
    local schema_path="${4:-/docker-entrypoint-initdb.d/01-schema.sql}"

    # Check if we need to apply schema
    if ! check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
        log "Applying consolidated schema.sql to fix missing tables/columns..."

        # Check if schema file exists in container
        if docker exec "$container_name" test -f "$schema_path" 2>/dev/null; then
            # Apply schema and capture output
            local result=$(docker exec -T "$container_name" psql -U "$db_user" -d "$db_name" -f "$schema_path" 2>&1)
            local exit_code=$?

            # Check for critical errors (ignore "already exists" and "does not exist" errors)
            # "does not exist" errors are often non-blocking - tables may be created later in the script
            local error_lines=$(echo "$result" | grep -i "error" | grep -vE "(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists|does not exist)" || true)

            local has_critical_errors=false
            if [ -n "$error_lines" ]; then
                # Check if errors are syntax errors or other blocking issues
                local blocking_errors=$(echo "$error_lines" | grep -vE "(relation.*does not exist|column.*does not exist)" || true)
                if [ -n "$blocking_errors" ]; then
                    err "Schema application encountered critical errors"
                    echo "$blocking_errors" | head -10
                    has_critical_errors=true
                else
                    log "Schema applied with some non-blocking errors (missing dependencies that may be created later)"
                fi
            elif echo "$result" | grep -qiE "error.*(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists)"; then
                log "Schema applied (some objects already existed - this is expected)"
            else
                ok "Schema applied successfully"
            fi

            # Even if there were errors, continue - the schema might have partially applied
            # We'll verify what actually exists in the validation step

            # Re-check after applying - if critical tables/columns exist, consider it successful
            # Wait for schema changes to be committed and visible
            # PostgreSQL may need time to commit large schema changes
            log "Waiting for schema changes to be committed..."
            sleep 10  # Increased wait time for large schema files

            # Force a connection refresh by running a simple query
            execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
            sleep 3  # Additional wait after connection refresh

            # Retry validation with exponential backoff (up to 3 attempts)
            local retry_count=0
            local max_retries=3
            local validation_passed=false

            while [ $retry_count -lt $max_retries ]; do
                if check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
                    validation_passed=true
                    break
                fi

                retry_count=$((retry_count + 1))
                if [ $retry_count -lt $max_retries ]; then
                    log "Validation failed, retrying in $((retry_count * 2)) seconds... (attempt $retry_count/$max_retries)"
                    sleep $((retry_count * 2))
                    # Force another connection refresh
                    execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                fi
            done

            if [ "$validation_passed" = true ]; then
                ok "All critical tables and columns now exist"
                return 0
            else
                # Final verification with direct queries to see if tables actually exist
                log "Re-checking critical tables/columns with direct queries..."
                local missing_count=0

                # Check all critical tables with direct queries (use EXISTS for better reliability)
                while IFS=':' read -r table_name service_name description; do
                    if [ -z "$table_name" ]; then
                        continue
                    fi

                    local table_exists=$(execute_sql "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$table_name');" "$container_name" "$db_user" "$db_name" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")
                    if [ "$table_exists" != "t" ]; then
                        warn "$table_name table still missing"
                        missing_count=$((missing_count + 1))
                    fi
                done <<< "$(get_critical_tables)"

                # Check critical columns with direct queries (use EXISTS for better reliability)
                while IFS=':' read -r column_ref description; do
                    if [ -z "$column_ref" ]; then
                        continue
                    fi

                    IFS='.' read -r table_name column_name <<< "$column_ref"
                    if [ -n "$table_name" ] && [ -n "$column_name" ]; then
                        local column_exists=$(execute_sql "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$table_name' AND column_name = '$column_name');" "$container_name" "$db_user" "$db_name" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")
                        if [ "$column_exists" != "t" ]; then
                            warn "$column_ref column still missing"
                            missing_count=$((missing_count + 1))
                        fi
                    fi
                done <<< "$(get_critical_columns)"

                if [ $missing_count -eq 0 ]; then
                    ok "All critical tables and columns exist (verified with direct queries)"
                    return 0
                else
                    # Try applying critical-tables.sql as a fallback
                    warn "Some critical tables/columns still missing after schema application"
                    log "Attempting to create missing tables directly..."

                    local critical_tables_sql="scripts/database/critical-tables.sql"
                    if [ -f "$critical_tables_sql" ]; then
                        local actual_container=$(get_container_name "$container_name")
                        docker cp "$critical_tables_sql" "$actual_container:/tmp/critical-tables.sql" >/dev/null 2>&1
                        if [ $? -eq 0 ]; then
                            local critical_result=$(docker exec -T "$actual_container" psql -U "$db_user" -d "$db_name" -f /tmp/critical-tables.sql 2>&1)
                            local critical_errors=$(echo "$critical_result" | grep -i "error" | grep -vE "(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists|does not exist)" || true)

                            if [ -z "$critical_errors" ]; then
                                log "Critical tables script applied successfully"
                                # Wait longer for changes to be committed and visible
                                sleep 10

                                # Force connection refresh
                                execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                                sleep 3

                                # Re-check with retries
                                local retry_count=0
                                local max_retries=3
                                while [ $retry_count -lt $max_retries ]; do
                                    if check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
                                        ok "All critical tables and columns now exist (after applying critical-tables.sql)"
                                        return 0
                                    fi
                                    retry_count=$((retry_count + 1))
                                    if [ $retry_count -lt $max_retries ]; then
                                        log "Re-checking after critical-tables.sql... (attempt $retry_count/$max_retries)"
                                        sleep $((retry_count * 2))
                                        execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                                    fi
                                done

                                # Final direct check
                                local final_check=$(execute_sql "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'report_templates');" "$container_name" "$db_user" "$db_name" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")
                                if [ "$final_check" = "t" ]; then
                                    ok "report_templates table exists (verified with direct query)"
                                    return 0
                                fi
                            else
                                warn "Critical tables script had errors:"
                                echo "$critical_errors" | head -5
                            fi
                        fi
                    fi

                    return 1
                fi
            fi
        else
            # Try copying from host
            local host_schema="scripts/database/schema.sql"
            if [ -f "$host_schema" ]; then
                log "Copying schema.sql from host to container..."
                # Get actual container name for docker cp (needs container name, not service name)
                local actual_container=$(get_container_name "$container_name")
                docker cp "$host_schema" "$actual_container:/tmp/schema.sql" >/dev/null 2>&1
                if [ $? -ne 0 ]; then
                    err "Failed to copy schema.sql to container"
                    return 1
                fi
                # Apply schema and capture output
                local result=$(docker exec -T "$actual_container" psql -U "$db_user" -d "$db_name" -f /tmp/schema.sql 2>&1)
                local exit_code=$?

                # Check for critical errors (ignore "already exists" errors as they're expected for idempotent schema)
                local error_lines=$(echo "$result" | grep -i "error" | grep -vE "(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists|does not exist)" || true)

                local has_critical_errors=false
                if [ -n "$error_lines" ]; then
                    # Check if errors are just about missing tables that will be created later (non-blocking)
                    local blocking_errors=$(echo "$error_lines" | grep -vE "(relation.*does not exist|column.*does not exist)" || true)
                    if [ -n "$blocking_errors" ]; then
                        err "Schema application encountered critical errors"
                        echo "$blocking_errors" | head -10
                        has_critical_errors=true
                    else
                        log "Schema applied with some non-blocking errors (missing dependencies that may be created later)"
                    fi
                elif echo "$result" | grep -qiE "error.*(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists)"; then
                    log "Schema applied (some objects already existed - this is expected)"
                else
                    ok "Schema applied successfully"
                fi

                # Even if there were errors, continue - the schema might have partially applied
                # We'll verify what actually exists in the validation step

                # Wait for schema changes to be committed and visible
                # Use a longer wait and verify with a direct query to ensure changes are visible
                # PostgreSQL may need time to commit large schema changes
                log "Waiting for schema changes to be committed..."
                sleep 10  # Increased wait time for large schema files

                # Force a connection refresh by running a simple query
                execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                sleep 3  # Additional wait after connection refresh

                # Retry validation with exponential backoff (up to 3 attempts)
                local retry_count=0
                local max_retries=3
                local validation_passed=false

                while [ $retry_count -lt $max_retries ]; do
                    if check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
                        validation_passed=true
                        break
                    fi

                    retry_count=$((retry_count + 1))
                    if [ $retry_count -lt $max_retries ]; then
                        log "Validation failed, retrying in $((retry_count * 2)) seconds... (attempt $retry_count/$max_retries)"
                        sleep $((retry_count * 2))
                        # Force another connection refresh
                        execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                    fi
                done

                if [ "$validation_passed" = true ]; then
                    ok "All critical tables and columns now exist"
                    return 0
                else
                    # Final verification with direct queries to see if tables actually exist
                    log "Re-checking critical tables/columns with direct queries..."
                    local missing_count=0

                    # Check all critical tables with direct queries (use EXISTS for better reliability)
                    while IFS=':' read -r table_name service_name description; do
                        if [ -z "$table_name" ]; then
                            continue
                        fi

                        local table_exists=$(execute_sql "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$table_name');" "$container_name" "$db_user" "$db_name" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")
                        if [ "$table_exists" != "t" ]; then
                            warn "$table_name table still missing"
                            missing_count=$((missing_count + 1))
                        fi
                    done <<< "$(get_critical_tables)"

                    # Check critical columns with direct queries (use EXISTS for better reliability)
                    while IFS=':' read -r column_ref description; do
                        if [ -z "$column_ref" ]; then
                            continue
                        fi

                        IFS='.' read -r table_name column_name <<< "$column_ref"
                        if [ -n "$table_name" ] && [ -n "$column_name" ]; then
                            local column_exists=$(execute_sql "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$table_name' AND column_name = '$column_name');" "$container_name" "$db_user" "$db_name" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")
                            if [ "$column_exists" != "t" ]; then
                                warn "$column_ref column still missing"
                                missing_count=$((missing_count + 1))
                            fi
                        fi
                    done <<< "$(get_critical_columns)"

                    if [ $missing_count -eq 0 ]; then
                        ok "All critical tables and columns exist (verified with direct queries)"
                        return 0
                    else
                        # Try applying critical-tables.sql as a fallback
                        warn "Some critical tables/columns still missing after schema application"
                        log "Attempting to create missing tables directly..."

                        local critical_tables_sql="scripts/database/critical-tables.sql"
                        if [ -f "$critical_tables_sql" ]; then
                            local actual_container=$(get_container_name "$container_name")
                            docker cp "$critical_tables_sql" "$actual_container:/tmp/critical-tables.sql" >/dev/null 2>&1
                            if [ $? -eq 0 ]; then
                                local critical_result=$(docker exec -T "$actual_container" psql -U "$db_user" -d "$db_name" -f /tmp/critical-tables.sql 2>&1)
                                local critical_errors=$(echo "$critical_result" | grep -i "error" | grep -vE "(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists|does not exist)" || true)

                                if [ -z "$critical_errors" ]; then
                                    log "Critical tables script applied successfully"
                                    # Wait longer for changes to be committed and visible
                                    sleep 10

                                    # Force connection refresh
                                    execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                                    sleep 3

                                    # Re-check with retries
                                    local retry_count=0
                                    local max_retries=3
                                    while [ $retry_count -lt $max_retries ]; do
                                        if check_critical_tables_and_columns "$container_name" "$db_user" "$db_name"; then
                                            ok "All critical tables and columns now exist (after applying critical-tables.sql)"
                                            return 0
                                        fi
                                        retry_count=$((retry_count + 1))
                                        if [ $retry_count -lt $max_retries ]; then
                                            log "Re-checking after critical-tables.sql... (attempt $retry_count/$max_retries)"
                                            sleep $((retry_count * 2))
                                            execute_sql "SELECT 1;" "$container_name" "$db_user" "$db_name" >/dev/null 2>&1
                                        fi
                                    done

                                    # Final direct check
                                    local final_check=$(execute_sql "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'report_templates');" "$container_name" "$db_user" "$db_name" | grep -E '^[[:space:]]*(t|f)' | tr -d ' ' || echo "f")
                                    if [ "$final_check" = "t" ]; then
                                        ok "report_templates table exists (verified with direct query)"
                                        return 0
                                    fi
                                else
                                    warn "Critical tables script had errors:"
                                    echo "$critical_errors" | head -5
                                fi
                            fi
                        fi

                        return 1
                    fi
                fi
            else
                warn "Schema file not found in container or host: $schema_path or $host_schema"
                return 1
            fi
        fi
    else
        return 0
    fi
}
