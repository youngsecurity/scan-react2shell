#!/bin/bash
#
# SYNOPSIS
#     Scans GitHub repositories for CVE-2025-55182 (React2Shell) vulnerability
# DESCRIPTION
#     Checks for vulnerable versions of React 19.x and Next.js 15.x that use
#     React Server Components (RSC) Flight protocol
# PARAMETER Path
#     Root directory containing GitHub repositories (default: current directory)
#

PATH_TO_SCAN="${1:-.}"

# Arrays to track results
declare -a VULNERABLE_REPOS=()
declare -a SAFE_REPOS=()
declare -a UNKNOWN_REPOS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN} CVE-2025-55182 (React2Shell) Scanner${NC}"
echo -e "${CYAN}========================================${NC}\n"

echo -e "${YELLOW}Scanning: $PATH_TO_SCAN${NC}\n"

# Find all package.json files, excluding node_modules
mapfile -t PACKAGE_FILES < <(find "$PATH_TO_SCAN" -name "package.json" -type f 2>/dev/null | grep -v "node_modules")

echo "Found ${#PACKAGE_FILES[@]} package.json files to analyze..."
echo ""

# Function to extract JSON value using grep/sed (portable, no jq dependency)
get_json_value() {
    local json="$1"
    local key="$2"
    echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed 's/.*"'$key'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | head -1
}

# Function to check if key exists in dependencies
has_dependency() {
    local json="$1"
    local dep="$2"
    echo "$json" | grep -q "\"$dep\"[[:space:]]*:"
}

for file in "${PACKAGE_FILES[@]}"; do
    if [[ -z "$file" ]]; then
        continue
    fi

    REPO_PATH=$(dirname "$file")
    REPO_NAME=$(basename "$(dirname "$file")")

    # Handle root-level package.json
    RESOLVED_PATH=$(cd "$PATH_TO_SCAN" 2>/dev/null && pwd)
    if [[ "$REPO_PATH" == "$RESOLVED_PATH" ]]; then
        REPO_NAME="[ROOT]"
    fi

    # Read package.json
    if ! PACKAGE_JSON=$(cat "$file" 2>/dev/null); then
        UNKNOWN_REPOS+=("$REPO_NAME|$file|Failed to read file")
        continue
    fi

    # Extract versions
    REACT_VERSION=$(get_json_value "$PACKAGE_JSON" "react")
    NEXT_VERSION=$(get_json_value "$PACKAGE_JSON" "next")

    HAS_REACT=false
    HAS_NEXT=false
    HAS_REACT_SERVER=false

    if has_dependency "$PACKAGE_JSON" "react"; then
        HAS_REACT=true
    fi

    if has_dependency "$PACKAGE_JSON" "next"; then
        HAS_NEXT=true
    fi

    if has_dependency "$PACKAGE_JSON" "react-server-dom-webpack" || has_dependency "$PACKAGE_JSON" "react-server-dom-esm"; then
        HAS_REACT_SERVER=true
    fi

    IS_VULNERABLE=false
    VULNERABILITY_DETAILS=""

    # Check React version (19.0.0 - 19.2.0 are vulnerable)
    if [[ "$REACT_VERSION" =~ 19\.[0-2]\. ]]; then
        IS_VULNERABLE=true
        VULNERABILITY_DETAILS="React $REACT_VERSION (vulnerable: 19.0.0-19.2.0)"
    fi

    # Check Next.js version (15.x before patch)
    if [[ "$NEXT_VERSION" =~ 15\. ]]; then
        IS_VULNERABLE=true
        if [[ -n "$VULNERABILITY_DETAILS" ]]; then
            VULNERABILITY_DETAILS="$VULNERABILITY_DETAILS; "
        fi
        VULNERABILITY_DETAILS="${VULNERABILITY_DETAILS}Next.js $NEXT_VERSION (vulnerable: 15.x before patch)"
    fi

    # Check for RSC packages
    if [[ "$HAS_REACT_SERVER" == true ]]; then
        if [[ -n "$VULNERABILITY_DETAILS" ]]; then
            VULNERABILITY_DETAILS="$VULNERABILITY_DETAILS; "
        fi
        VULNERABILITY_DETAILS="${VULNERABILITY_DETAILS}Uses React Server Components packages"
    fi

    # Check for "use server" directives in source files
    if find "$REPO_PATH" -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" \) 2>/dev/null | grep -v "node_modules" | head -100 | xargs grep -l '"use server"' 2>/dev/null | head -1 | grep -q .; then
        if [[ -n "$VULNERABILITY_DETAILS" ]]; then
            VULNERABILITY_DETAILS="$VULNERABILITY_DETAILS; "
        fi
        VULNERABILITY_DETAILS="${VULNERABILITY_DETAILS}Contains 'use server' directives (Server Actions)"
    fi

    # Categorize
    if [[ "$IS_VULNERABLE" == true ]]; then
        VULNERABLE_REPOS+=("$REPO_NAME|$file|$VULNERABILITY_DETAILS|$REACT_VERSION|$NEXT_VERSION")
    elif [[ "$HAS_REACT" == true ]] || [[ "$HAS_NEXT" == true ]]; then
        SAFE_REPOS+=("$REPO_NAME|$file|$REACT_VERSION|$NEXT_VERSION")
    fi
done

# Output Results
echo -e "\n${RED}========================================${NC}"
echo -e "${RED} VULNERABLE REPOSITORIES (${#VULNERABLE_REPOS[@]})${NC}"
echo -e "${RED}========================================${NC}"

if [[ ${#VULNERABLE_REPOS[@]} -gt 0 ]]; then
    for repo in "${VULNERABLE_REPOS[@]}"; do
        IFS='|' read -r name path details react_ver next_ver <<< "$repo"
        echo -e "\n${RED}[!] $name${NC}"
        echo -e "${GRAY}    Path: $path${NC}"
        echo -e "${YELLOW}    Issue: $details${NC}"
    done

    echo -e "\n${RED}----------------------------------------${NC}"
    echo -e "${RED} REMEDIATION REQUIRED:${NC}"
    echo -e "${RED}----------------------------------------${NC}"
    echo -e "${WHITE} - React: Upgrade to 19.2.1 or later${NC}"
    echo -e "${WHITE} - Next.js: Upgrade to 15.2.4 or later${NC}"
    echo -e "${CYAN} - See: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components${NC}"
else
    echo -e "\n${GREEN}No vulnerable repositories found!${NC}"
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN} SAFE REPOSITORIES (${#SAFE_REPOS[@]})${NC}"
echo -e "${GREEN}========================================${NC}"

for repo in "${SAFE_REPOS[@]}"; do
    IFS='|' read -r name path react_ver next_ver <<< "$repo"
    VERSIONS=""
    if [[ -n "$react_ver" ]]; then
        VERSIONS="React: $react_ver"
    fi
    if [[ -n "$next_ver" ]]; then
        if [[ -n "$VERSIONS" ]]; then
            VERSIONS="$VERSIONS, "
        fi
        VERSIONS="${VERSIONS}Next: $next_ver"
    fi
    echo -e "${GREEN}  [OK] $name - $VERSIONS${NC}"
done

if [[ ${#UNKNOWN_REPOS[@]} -gt 0 ]]; then
    echo -e "\n${YELLOW}========================================${NC}"
    echo -e "${YELLOW} PARSE ERRORS (${#UNKNOWN_REPOS[@]})${NC}"
    echo -e "${YELLOW}========================================${NC}"
    for repo in "${UNKNOWN_REPOS[@]}"; do
        IFS='|' read -r name path error <<< "$repo"
        echo -e "${YELLOW}  [?] $name: $error${NC}"
    done
fi

echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN} SCAN COMPLETE${NC}"
echo -e "${CYAN}========================================${NC}"
echo " Total package.json scanned: ${#PACKAGE_FILES[@]}"

if [[ ${#VULNERABLE_REPOS[@]} -gt 0 ]]; then
    echo -e "${RED} Vulnerable: ${#VULNERABLE_REPOS[@]}${NC}"
else
    echo -e "${GREEN} Vulnerable: 0${NC}"
fi

echo -e "${GREEN} Safe (React/Next but not vulnerable): ${#SAFE_REPOS[@]}${NC}"
echo -e "${YELLOW} Parse errors: ${#UNKNOWN_REPOS[@]}${NC}"

# Export results to CSV if vulnerable repos found
if [[ ${#VULNERABLE_REPOS[@]} -gt 0 ]]; then
    CSV_PATH="$PATH_TO_SCAN/cve-2025-55182-scan-results.csv"
    echo "Name,Path,Details,ReactVersion,NextVersion" > "$CSV_PATH"
    for repo in "${VULNERABLE_REPOS[@]}"; do
        IFS='|' read -r name path details react_ver next_ver <<< "$repo"
        echo "\"$name\",\"$path\",\"$details\",\"$react_ver\",\"$next_ver\"" >> "$CSV_PATH"
    done
    echo -e "\n${CYAN}Results exported to: $CSV_PATH${NC}"
fi
