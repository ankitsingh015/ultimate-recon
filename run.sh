#!/usr/bin/env bash

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_usage() {
    echo "Usage: ./run.sh <target> [options]"
    echo ""
    echo "Full Pipeline:"
    echo "  ./run.sh example.com                          Full recon (all 5 phases)"
    echo "  ./run.sh example.com --stealth                Skip aggressive scans"
    echo "  ./run.sh example.com --phase 1,2              Run specific phases only"
    echo ""
    echo "Single Tool Mode (run one tool + AI analysis):"
    echo "  ./run.sh example.com --tool subfinder         Run subfinder, save + analyze"
    echo "  ./run.sh example.com --tool httpx --output ~/myrecon  Custom output dir"
    echo "  ./run.sh example.com --tool nuclei --output ./results   Save anywhere"
    echo ""
    echo "Tool Management:"
    echo "  ./run.sh --list-tools                         List all 65+ available tools"
    echo "  ./run.sh --list-tools --category subdomain     Filter by category"
    echo ""
    echo "Options:"
    echo "  --tool NAME     Run a single tool (see --list-tools)"
    echo "  -o, --output    Custom output directory for single tool results"
    echo "  --list-tools    List all available single tools"
    echo "  --category CAT  Filter --list-tools by category"
    echo "  --stealth       Skip aggressive scans"
    echo "  --phase N       Run specific phase(s) only (e.g., --phase 1,2)"
    echo "  --resume        Resume from last checkpoint"
    echo "  --only-missing  Only run tools with newly configured API keys"
    echo "  --docker        Force Docker mode"
    echo "  --native        Force native mode"
    echo "  --help, -h      Show this help"
    echo ""
    echo "Docker:"
    echo "  docker build -t ultimate-recon ."
    echo "  docker run -v \$(pwd)/output:/opt/ultimate-recon/output ultimate-recon example.com"
    echo "  docker run --tool subfinder example.com       Single tool in Docker"
    echo ""
    echo "Report:"
    echo "  open output/example.com/report.html"
}

if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    print_usage
    exit 0
fi

TARGET="$1"
shift 2>/dev/null || true

USE_DOCKER=false
USE_NATIVE=false
EXTRA_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --docker) USE_DOCKER=true ;;
        --native) USE_NATIVE=true ;;
        --stealth|--resume|--only-missing) EXTRA_ARGS+=("$arg") ;;
        --phase) EXTRA_ARGS+=("$arg" "$2"); shift ;;
        *) EXTRA_ARGS+=("$arg") ;;
    esac
done

if [ "$USE_DOCKER" = true ] || ([ "$USE_NATIVE" != true ] && command -v docker &>/dev/null && docker info &>/dev/null 2>&1); then
    echo -e "${CYAN}[*] Using Docker mode${NC}"

    if ! docker image inspect ultimate-recon:latest &>/dev/null; then
        echo -e "${YELLOW}[!] Docker image not found. Building...${NC}"
        docker build -t ultimate-recon:latest .
        echo -e "${GREEN}[✓] Build complete${NC}"
    fi

    OUTPUT_DIR="$SCRIPT_DIR/output"
    CONFIG_DIR="$SCRIPT_DIR/config"
    mkdir -p "$OUTPUT_DIR" "$CONFIG_DIR"

    echo -e "${GREEN}[*] Running container...${NC}"
    docker run --rm \
        --network host \
        -v "$OUTPUT_DIR:/opt/ultimate-recon/output" \
        -v "$CONFIG_DIR:/opt/ultimate-recon/config" \
        -e PYTHONUNBUFFERED=1 \
        ultimate-recon:latest \
        "$TARGET" "${EXTRA_ARGS[@]}"

    echo ""
    echo -e "${GREEN}[✓] Done. Report:${NC}"
    echo "  $OUTPUT_DIR/$TARGET/report.html"
    echo "  Open: file://$OUTPUT_DIR/$TARGET/report.html"
else
    echo -e "${CYAN}[*] Using Native mode${NC}"

    PYTHON="python3"
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[!] Python3 not found. Run ./setup.sh first.${NC}"
        exit 1
    fi

    SCRIPT="$SCRIPT_DIR/src/orchestrator.py"
    if [ ! -f "$SCRIPT" ]; then
        echo -e "${RED}[!] orchestrator.py not found at $SCRIPT${NC}"
        exit 1
    fi

    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
    exec $PYTHON "$SCRIPT" "$TARGET" "${EXTRA_ARGS[@]}"
fi
