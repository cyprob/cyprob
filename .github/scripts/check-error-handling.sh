#!/usr/bin/env bash
# check-error-handling.sh
# Enforces CLI error handling standards by detecting banned patterns.
#
# Usage:
#   check-error-handling.sh <path> <banned_pattern> <suggestion>
#
# Arguments:
#   path            - Directory to scan (e.g., cmd/cyprob/commands/plugin)
#   banned_pattern  - Regex pattern to detect (e.g., 'return\s+formatter\.PrintError\s*\(')
#   suggestion      - Guidance message for developers
#
# Exit codes:
#   0 - No violations found
#   1 - Violations detected (fails CI)
#   2 - Invalid arguments or setup error
#
# Features:
#   - Uses ripgrep (rg) if available, falls back to grep
#   - Excludes test files (*_test.go)
#   - Excludes comment-only lines (reduces false positives)
#   - Reports file:line for each violation

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Arguments
if [ $# -ne 3 ]; then
    echo -e "${RED}Error: Invalid arguments${NC}" >&2
    echo "Usage: $0 <path> <banned_pattern> <suggestion>" >&2
    exit 2
fi

PATH_TO_SCAN="$1"
BANNED_PATTERN="$2"
SUGGESTION="$3"

# Validate path exists
if [ ! -d "$PATH_TO_SCAN" ]; then
    echo -e "${YELLOW}(info) Path does not exist: $PATH_TO_SCAN${NC}"
    echo -e "${GREEN}✅ No violations found (path does not exist)${NC}"
    exit 0
fi

echo -e "${BLUE}🔍 Checking error handling patterns in: $PATH_TO_SCAN${NC}"
echo -e "${BLUE}   Banned pattern: $BANNED_PATTERN${NC}"
echo ""

# Detect available search tool and run scan
if command -v rg >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Using ripgrep (faster)${NC}"
    echo ""

    # ripgrep command:
    # -n: show line numbers
    # -t go: only Go files
    # -g '!*_test.go': exclude test files
    # -g '!**/*.md': exclude markdown
    # --color never: no ANSI colors in output
    # -e "$BANNED_PATTERN": search for pattern
    # "$PATH_TO_SCAN": scan path
    VIOLATIONS=$(rg -n -t go -g '!*_test.go' -g '!**/*.md' --color never -e "$BANNED_PATTERN" "$PATH_TO_SCAN" || true)
else
    echo -e "${YELLOW}⚠ ripgrep not found, using grep (slower)${NC}"
    echo ""

    # grep command:
    # -RIn: recursive, line numbers, skip binary
    # -E: extended regex
    # "$BANNED_PATTERN": search for pattern
    # "$PATH_TO_SCAN": scan path
    # Filter out test files and comments
    VIOLATIONS=$(grep -RInE "$BANNED_PATTERN" "$PATH_TO_SCAN" \
        | grep -v "_test.go" \
        | grep -vE "^[[:space:]]*//" || true)
fi

# Check if violations found
if [ -n "$VIOLATIONS" ]; then
    echo -e "${RED}❌ Error handling standard violations detected:${NC}"
    echo ""
    echo "$VIOLATIONS"
    echo ""
    echo -e "${YELLOW}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}📚 Standard:${NC}"
    echo -e "   $SUGGESTION"
    echo -e "${YELLOW}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${RED}Please update the above files to follow the error handling standard.${NC}"
    echo ""
    exit 1
else
    echo -e "${GREEN}✅ No violations found - error handling standard compliance OK${NC}"
    echo ""
    exit 0
fi
