#!/usr/bin/env bash

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║        Ultimate Recon — Setup Script            ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "macos";;
        *)          echo "unknown";;
    esac
}

get_package_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v brew &>/dev/null; then
        echo "brew"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    else
        echo "unknown"
    fi
}

check_docker() {
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        return 0
    fi
    return 1
}

OS=$(detect_os)
PKG_MANAGER=$(get_package_manager)

echo -e "${BOLD}System:${NC} $OS"
echo -e "${BOLD}Package Manager:${NC} $PKG_MANAGER"
echo ""

if check_docker; then
    echo -e "${GREEN}[✓] Docker detected${NC}"
    echo ""
    echo -e "Recommended: ${BOLD}docker build -t ultimate-recon .${NC}"
    echo ""
    echo "Docker handles all dependencies automatically."
    echo "To build and run:"
    echo "  docker build -t ultimate-recon ."
    echo "  docker run -v \$(pwd)/output:/opt/ultimate-recon/output ultimate-recon example.com"
    echo ""
    read -p "Build Docker image now? (y/N): " build_docker
    if [[ "$build_docker" =~ ^[Yy]$ ]]; then
        echo -e "\n${BOLD}Building Docker image...${NC}"
        docker build -t ultimate-recon .
        echo -e "\n${GREEN}[✓] Docker image built successfully${NC}"
        echo "Run: docker run -v \$(pwd)/output:/opt/ultimate-recon/output ultimate-recon example.com"
    fi
    exit 0
fi

echo -e "${YELLOW}[!] Docker not found. Setting up native environment...${NC}"
echo ""

if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}[!] Python3 not found. Installing...${NC}"
    case "$PKG_MANAGER" in
        apt) sudo apt-get install -y python3 python3-pip ;;
        brew) brew install python3 ;;
        *) echo -e "${RED}[!] Please install Python 3.8+ manually${NC}"; exit 1 ;;
    esac
fi

if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}[!] Go not found. Installing...${NC}"
    case "$PKG_MANAGER" in
        apt) sudo apt-get install -y golang-go ;;
        brew) brew install go ;;
        *) echo -e "${RED}[!] Please install Go manually${NC}"; exit 1 ;;
    esac
fi

echo -e "${GREEN}[✓] Python3 and Go available${NC}"

echo -e "\n${BOLD}Installing system packages...${NC}"
SYSTEM_PACKAGES="curl wget git jq nmap masscan dnsutils whatweb sqlmap wafw00f ffuf"
case "$PKG_MANAGER" in
    apt)
        sudo apt-get update
        sudo apt-get install -y $SYSTEM_PACKAGES build-essential libpcap-dev python3-pip
        ;;
    brew)
        brew install $SYSTEM_PACKAGES
        ;;
    *)
        echo -e "${YELLOW}[!] Please install manually: $SYSTEM_PACKAGES${NC}"
        ;;
esac

echo -e "\n${BOLD}Installing Go tools...${NC}"
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/findomain/findomain@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/lc/subjs@latest"
    "github.com/tomnomnom/hakrawler@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/michenriksen/aquatone@latest"
    "github.com/003random/getJS@latest"
    "github.com/KathanP19/urlfinder@latest"
    "github.com/Josue87/gospider@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/tomnomnom/waybackurls@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "$tool" | cut -d@ -f1)
    if ! command -v "$name" &>/dev/null; then
        echo "  Installing $name..."
        go install -v "$tool" 2>/dev/null || echo "  [!] Failed: $name"
    else
        echo "  [✓] $name already installed"
    fi
done

echo -e "\n${BOLD}Installing Python packages...${NC}"
PYTHON_PACKAGES=(
    "requests" "beautifulsoup4" "lxml" "jinja2" "pyyaml"
    "tqdm" "colorama" "rich" "arjun" "uro" "dirsearch" "gf"
)
pip3 install --upgrade pip
for pkg in "${PYTHON_PACKAGES[@]}"; do
    pip3 install --quiet "$pkg" 2>/dev/null && echo "  [✓] $pkg" || echo "  [!] Failed: $pkg"
done

echo -e "\n${BOLD}Cloning wordlists and payloads...${NC}"
if [ ! -d "/usr/share/seclists" ]; then
    echo "  Cloning SecLists (large download)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || echo "  [!] Failed to clone SecLists"
fi

if [ ! -d "/opt/payloads" ]; then
    git clone --depth 1 https://github.com/coffinxp/payloads.git /opt/payloads 2>/dev/null || echo "  [!] Failed"
fi

echo -e "\n${BOLD}Setting up nuclei templates...${NC}"
nuclei -update-templates 2>/dev/null || echo "  [!] Failed to update templates"

echo -e "\n${BOLD}Configuring API keys...${NC}"
if [ ! -f ".env" ] && [ ! -f "config/api-keys.yaml" ]; then
    echo ""
    echo "  API keys are OPTIONAL — the tool works without them."
    echo "  Without keys, only public data sources are used."
    echo ""
    read -p "  Set up API keys now? (y/N): " setup_keys
    if [[ "$setup_keys" =~ ^[Yy]$ ]]; then
        cp .env.example .env
        echo ""
        echo "  Edit .env to add your API keys:"
        echo "    nano .env"
        echo "    vim .env"
        echo ""
        echo "  Supported keys:"
        echo "    GITHUB_TOKEN     — GitHub subdomain scraping"
        echo "    SHODAN_API_KEY   — Shodan-powered recon"
        echo "    VIRUSTOTAL_API_KEY — VirusTotal domain info"
        echo "    CHAOS_API_KEY    — ProjectDiscovery Chaos"
        echo ""
    else
        echo "  Skipping API key setup. Pass --setup-keys anytime to configure later."
    fi
else
    echo "  [✓] API keys already configured"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Setup Complete!                                  ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  Quick start:                                     ║${NC}"
echo -e "${GREEN}║    ./run.sh example.com                           ║${NC}"
echo -e "${GREEN}║    ./run.sh example.com --tool subfinder          ║${NC}"
echo -e "${GREEN}║    ./run.sh --list-tools                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
