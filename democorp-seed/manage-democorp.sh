#!/bin/bash
# =================================================================
# DemoCorp Seed Data Manager
# =================================================================
# Interactive script to load or erase DemoCorp tenant and data
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

show_menu() {
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${CYAN}DemoCorp Seed Data Manager${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo ""
    echo "1. Load DemoCorp tenant and data"
    echo "2. Erase DemoCorp tenant (all data)"
    echo "3. Erase DemoCorp data only (keep tenant)"
    echo "4. Exit"
    echo ""
}

while true; do
    show_menu
    read -p "Enter choice [1-4]: " choice

    case $choice in
        1)
            echo ""
            "$SCRIPT_DIR/load-democorp.sh"
            echo ""
            read -p "Press Enter to continue..."
            ;;
        2)
            echo ""
            "$SCRIPT_DIR/erase-democorp.sh"
            echo ""
            read -p "Press Enter to continue..."
            ;;
        3)
            echo ""
            echo -e "${YELLOW}Erasing DemoCorp data only (keeping tenant and users)...${NC}"
            echo -e "${YELLOW}If you cannot log in afterward, run option 1 (Load) and choose to erase and recreate.${NC}"
            DB_CONTAINER="${DB_CONTAINER:-crypto-postgres}"
            DB_USER="${DB_USER:-crypto_user}"
            DB_NAME="${DB_NAME:-crypto_inventory}"

            if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
                echo -e "${RED}Error: Container ${DB_CONTAINER} is not running${NC}"
            else
                read -p "Are you sure? (yes/no): " confirm
                if [ "$confirm" = "yes" ]; then
                    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/erase-data.sql"
                    echo -e "${GREEN}✓ DemoCorp inventory data erased successfully${NC}"
                    echo -e "${GREEN}  Tenant and users remain intact${NC}"
                else
                    echo -e "${YELLOW}Cancelled.${NC}"
                fi
            fi
            echo ""
            read -p "Press Enter to continue..."
            ;;
        4)
            echo -e "${BLUE}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please enter 1-4.${NC}"
            sleep 2
            ;;
    esac
done
