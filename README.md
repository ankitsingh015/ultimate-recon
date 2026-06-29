<div align="center">

# 🛡️ Ultimate Recon

**61+ Bug Bounty Recon Tools · 5-Phase Automated Pipeline · AI Analysis · Web Dashboard**

[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Kali](https://img.shields.io/badge/Kali%20Linux-Based-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen)](https://github.com/ankitsingh015/ultimate-recon/pulls)

```
  _   _ _ _        _             _    ____                      _
 | | | (_) |      | |           | |  |  _ \                    | |
 | | | |_| |_ __ _| | ___   __ _| |  | |_) | ___  ___ ___   __| | ___ _ __
 | | | | | __/ _` | |/ _ \ / _` | |  |  _ < / _ \/ __/ _ \ / _` |/ _ \ '__|
 | |_| | | || (_| | | (_) | (_| | |  | |_) |  __/ (_| (_) | (_| |  __/ |
  \___/|_|\__\__,_|_|\___/ \__,_|_|  |____/ \___|\___\___/ \__,_|\___|_|
```

**For authorized security testing only.**

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🚀 **Full Automation** | One command — from subdomains to HTML report |
| 🔍 **61+ Tools** | Subdomain discovery, URL crawling, param analysis, vuln scanning, screenshots |
| 🧠 **AI-Powered Analysis** | Rule-based categorization + optional OpenAI/Anthropic/Ollama integration |
| 🌐 **Web Dashboard** | Flask UI to browse past results, raw files, screenshots, and analysis |
| 📦 **Docker Ready** | Single image, zero dependencies on host — build once, run anywhere |
| 🎯 **Single Tool Mode** | Run any tool individually with AI analysis |
| ⚡ **Stealth Mode** | Skip aggressive scans (ports, dir brute-force) |
| 🔄 **Resume Support** | Pick up where you left off after interruption |
| 🗂️ **Organized Output** | Structured workspace per target with raw results, analysis, and report |

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/ankitsingh015/ultimate-recon.git
cd ultimate-recon

# 2. Build the image (5-10 minutes first time)
docker build -t ultimate-recon .

# 3. Run against a target (results save to ./output/)
docker run --network host \
  -v $(pwd)/output:/opt/ultimate-recon/workspaces \
  ultimate-recon example.com --ai disabled

# 4. Open the report
open output/example.com/report.html
```

> ⏱️ First build takes 5-10 minutes to download all tools. Subsequent runs use Docker cache.

---

## 📋 Pipeline Overview

The tool runs 5 phases automatically, each feeding into the next:

```
INPUT: example.com
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  PHASE 1  🎯 Asset Discovery                       │
│  ───────────────────────────────────────────────── │
│  22 parallel tasks: subfinder, amass, assetfinder,  │
│  crt.sh, wayback, urlscan, dnsrecon, chaos, ...     │
│  + permutation generation (alterx) + brute-force    │
│  + DNS resolution (dnsx, shuffledns)                │
│  + ASN/IP mapping (asnmap)                          │
│  Output: all-subdomains.txt, resolved-ips.txt       │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  PHASE 2  🌐 Live Hosts & URLs                     │
│  ───────────────────────────────────────────────── │
│  HTTP probing (httpx), URL collection (gau, katana, │
│  waymore, gospider), screenshots (gowitness),       │
│  tech detection (whatweb, wafw00f)                  │
│  Output: alive-hosts.txt, all-urls.txt, screenshots │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  PHASE 3  🔍 Deep Recon                            │
│  ───────────────────────────────────────────────── │
│  Parameter extraction (gf, arjun), JS analysis      │
│  (subjs, getJS, linkfinder, secretfinder),          │
│  port scanning (naabu, nmap, rustscan, masscan),    │
│  directory brute-force (dirsearch, ffuf),           │
│  cloud asset enumeration (s3scanner, cloud_enum)    │
│  Output: params/, js-secrets.txt, open-ports.txt    │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  PHASE 4  💥 Vulnerability Testing                 │
│  ───────────────────────────────────────────────── │
│  nuclei (1000+ templates), SQLi (sqlmap),           │
│  XSS (dalfox), CORS (corsy), SSTI (sstimap),        │
│  command injection (commix), subdomain takeover     │
│  (subzy), WPScan, git exposure, SSRF, LFI           │
│  Output: vulnerabilities.json                       │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  PHASE 5  📄 Report Generation                     │
│  ───────────────────────────────────────────────── │
│  HTML report with findings, evidence, screenshots,  │
│  attack chains, AI recommendations                  │
│  Output: report.html                                │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
                OUTPUT: report.html ✅
```

---

## 📦 Installation

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/ankitsingh015/ultimate-recon.git
cd ultimate-recon
docker build -t ultimate-recon .
```

The multi-stage Dockerfile compiles all Go tools in a builder stage, then creates a minimal runtime image with Kali Linux, Python tools, and binary artifacts.

### Option 2: Native (Linux)

```bash
./setup.sh       # Installs Go tools, Python deps, wordlists
./run.sh example.com
```

> ⚠️ Native mode requires Go 1.24+, Python 3.10+, and 10GB+ disk space for wordlists.

---

## 🎯 Usage Examples

### Full Recon Pipeline

```bash
# Run everything (all 5 phases)
docker run --network host \
  -v $(pwd)/output:/opt/ultimate-recon/workspaces \
  ultimate-recon example.com --ai disabled

# With interactive AI prompts (use -it for TTY)
docker run --network host -it \
  -v $(pwd)/output:/opt/ultimate-recon/workspaces \
  ultimate-recon example.com
```

### Run Specific Phases

```bash
# Passive recon only
docker run --network host ultimate-recon example.com --phase 1

# Active recon + vuln testing (skip asset discovery)
docker run --network host ultimate-recon example.com --phase 2,3,4

# Report only (if you already have results)
docker run --network host ultimate-recon example.com --phase 5
```

### Stealth Mode

Skips aggressive scans (port scanning, directory brute-force):

```bash
docker run --network host ultimate-recon example.com --stealth
```

### Single Tool Mode

Run any of the 61 tools individually:

```bash
# Subdomain discovery
docker run --network host ultimate-recon example.com --tool subfinder

# URL crawling
docker run --network host ultimate-recon example.com --tool gau

# Vulnerability scanning
docker run --network host ultimate-recon example.com --tool nuclei

# Save output to a custom location
docker run --network host ultimate-recon example.com --tool httpx --output /custom/path
```

### List Available Tools

```bash
# All tools
docker run --network host ultimate-recon --list-tools

# Filter by category
docker run --network host ultimate-recon --list-tools --category subdomain
docker run --network host ultimate-recon --list-tools --category vuln
```

### Other Commands

```bash
# Resume from last checkpoint
docker run --network host ultimate-recon example.com --resume

# Interactive API key setup
docker run --network host ultimate-recon --setup-keys
```

---

## 🤖 AI Integration

The tool has a pluggable AI provider system for analyzing results between phases.

| Provider | Command | Description |
|----------|---------|-------------|
| **opencode** (default) | `--ai opencode` | Rule-based categorization + interactive prompt. Analyzes subdomains, generates recommendations, and asks for your input to guide the next phase. **No API keys needed.** |
| **disabled** | `--ai disabled` | Fully silent — no prompts, no analysis display. Best for automated/CI pipelines. |
| openai | *(future)* | Enable in `config/ai-providers.yaml` — requires `OPENAI_API_KEY` |
| anthropic | *(future)* | Enable in `config/ai-providers.yaml` — requires `ANTHROPIC_API_KEY` |
| ollama | *(future)* | Enable in `config/ai-providers.yaml` — uses local LLM at `localhost:11434` |

### How AI Analysis Works

After each phase, the AI engine:
1. Collects all raw results (subdomains, URLs, parameters, vulnerabilities)
2. Categorizes findings by type (admin, api, dev, cloud, database, etc.)
3. Generates security recommendations (e.g., "3 dev hosts found — prioritize testing")
4. (Interactive mode) Asks what you want to focus on next
5. Saves all decisions to `chat.jsonl` for review in the web dashboard

### API Keys (Optional)

```bash
cp .env.example .env
# Edit .env with your keys — only key-dependent tools are skipped if missing
```

Supported: `GITHUB_TOKEN`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `CHAOS_API_KEY`, `SECURITYTRAILS_API_KEY`, `URLSCAN_API_KEY`, `HACKERTARGET_API_KEY`, `ALIENVAULT_API_KEY`, `BEVIGIL_API_KEY`, `ZOOMEYE_API_KEY`, `FACEBOOK_API_KEY`

---

## 🌐 Web Dashboard

The built-in Flask web UI lets you browse past scan results in a browser.

```bash
# Launch the dashboard (after at least one scan)
docker run --network host \
  -v $(pwd)/output:/opt/ultimate-recon/workspaces \
  ultimate-recon --web
```

Open **http://localhost:5000** in your browser.

| Page | Description |
|------|-------------|
| `/` | Workspace list — all targets you've scanned |
| `/workspace/<name>` | Full details: session log, raw results, screenshots, analysis files |
| `/workspace/<name>/report` | HTML report |
| `/workspace/<name>/chat` | AI chat history |
| `/workspace/<name>/raw/<file>` | View any raw result file |
| `/workspace/<name>/screenshots/<file>` | View screenshots |

> The web UI is a **read-only viewer**. It displays results from past scans — it does not launch new scans.

---

## 📁 Output Structure

When you run with `-v $(pwd)/output:/opt/ultimate-recon/workspaces`, results save to your machine:

```
output/
└── example.com/                    # One folder per target
    ├── all_results/                # Raw tool output files
    │   ├── subfinder.txt           #   Subdomain discovery results
    │   ├── httpx.txt               #   Live host probing
    │   ├── gau.txt                 #   URL collection
    │   ├── nuclei.txt              #   Vulnerability scan results
    │   ├── nmap.txt                #   Port scan results
    │   └── ...                     #   All other tool outputs
    │
    ├── analysis/                   # AI analysis
    │   ├── phase1-analysis.json    #   Phase analysis in JSON
    │   ├── phase1-summary.txt      #   Phase summary in text
    │   ├── full-analysis.json      #   Complete analysis
    │   └── highlights.txt          #   Critical findings summary
    │
    ├── ai_decisions/               # AI decision logs
    │   ├── phase1-prompt.txt       #   What was sent to AI
    │   └── phase1-response.json    #   AI analysis result
    │
    ├── screenshots/                # Website screenshots (from gowitness/aquatone)
    │   ├── example.com.png
    │   └── ...
    │
    ├── report.html                 # 📄 Final HTML report — open this
    ├── chat.jsonl                  # AI chat history
    ├── recon.db                    # SQLite database
    ├── session.jsonl               # Session timeline
    ├── config.yaml                 # Workspace-specific config
    └── target.yaml                 # Target metadata
```

---

## 🛠️ All 61 Tools

<details>
<summary><b>🔎 Subdomain Discovery</b> (18 tools) — Click to expand</summary>

| Tool | Description |
|------|-------------|
| `subfinder` | Passive subdomain enumeration using multiple sources |
| `assetfinder` | Find subdomains from various public sources |
| `findomain` | Subdomain discovery via certificate transparency + APIs |
| `amass_passive` | OWASP Amass — passive subdomain enumeration |
| `crtsh` | Certificate transparency log search |
| `wayback` | Wayback Machine CDX API for historical subdomains |
| `urlscan` | URLScan.io API for subdomain discovery |
| `hackertarget` | HackerTarget API subdomain search |
| `commoncrawl` | CommonCrawl index subdomain extraction |
| `virustotal` | VirusTotal API subdomain lookup |
| `github_subdomains` | GitHub subdomain enumeration via search |
| `shosubgo` | Shodan subdomain enumeration |
| `chaos` | ProjectDiscovery Chaos API |
| `dnsrecon` | DNS record enumeration |
| `haktrails` | SecurityTrails API subdomain discovery |
| `alterx` | Subdomain permutation generation |
| `shuffledns` | DNS brute-force resolver |
| `dnsx` | Fast multi-threaded DNS resolver |

</details>

<details>
<summary><b>🌐 URL & Crawling</b> (6 tools) — Click to expand</summary>

| Tool | Description |
|------|-------------|
| `gau` | Get all URLs from Wayback, AlienVault, etc. |
| `waymore` | Enhanced Wayback Machine URL collector |
| `katana` | ProjectDiscovery web crawler |
| `gospider` | Fast web spider with JS parsing |
| `hakrawler` | Minimal web crawler for reconnaissance |
| `urlfinder` | URL discovery from various sources |

</details>

<details>
<summary><b>📝 Parameter Analysis</b> (6 tools) — Click to expand</summary>

| Tool | Description |
|------|-------------|
| `gf_sqli` | Filter URLs with SQLi potential |
| `gf_xss` | Filter URLs with XSS potential |
| `gf_lfi` | Filter URLs with LFI potential |
| `gf_ssrf` | Filter URLs with SSRF potential |
| `gf_redirect` | Filter URLs with Open Redirect potential |
| `arjun` | HTTP parameter discovery suite |

</details>

<details>
<summary><b>💻 JavaScript Analysis</b> (4 tools) — Click to expand</summary>

| Tool | Description |
|------|-------------|
| `subjs` | JavaScript file discovery from URLs |
| `getJS` | Extract JavaScript files from web pages |
| `linkfinder` | Extract endpoints from JavaScript files |
| `secretfinder` | Find secrets in JS files (API keys, tokens) |

</details>

<details>
<summary><b>🔌 Port Scanning</b> (4 tools) — Click to expand</summary>

| Tool | Description |
|------|-------------|
| `naabu` | ProjectDiscovery fast port scanner |
| `nmap` | Industry-standard port scanner |
| `rustscan` | Ultra-fast port scanner (Rust) |
| `masscan` | Massively parallel port scanner |

</details>

<details>
<summary><b>💥 Vulnerability</b> (8 tools) — Click to expand</summary>

| Tool | Description |
|------|-------------|
| `nuclei` | Template-based vulnerability scanner (1000+ templates) |
| `sqlmap` | Automatic SQL injection detection & exploitation |
| `dalfox` | Advanced XSS scanner |
| `corsy` | CORS misconfiguration checker |
| `subzy` | Subdomain takeover checker |
| `wpscan` | WordPress vulnerability scanner |
| `sstimap` | Server-Side Template Injection detection |
| `commix` | Command injection detection |

</details>

<details>
<summary><b>Other Tools</b> (15 tools) — Click to expand</summary>

| Category | Tools |
|----------|-------|
| **Directory** (2) | `dirsearch`, `ffuf_dir` |
| **Technology** (2) | `whatweb`, `wafw00f` |
| **Screenshot** (2) | `gowitness`, `aquatone` |
| **Cloud** (2) | `s3scanner`, `cloud_enum` |
| **Git** (2) | `gitdumper`, `nuclei_git` |
| **Fuzzing** (1) | `ffuf` |
| **Live Host** (1) | `httpx` |
| **IP/ASN** (1) | `asnmap` |
| **Utility** (2) | `qsreplace`, `uro` |

</details>

---

## 📖 Command Reference

| Flag | Description |
|------|-------------|
| `--tool <name>` | Run a single tool by name |
| `--output, -o <path>` | Custom output directory |
| `--phase <n>` | Specific phase(s): `1`, `1,2,3`, `1,2,3,4,5` |
| `--stealth` | Skip aggressive scans (ports, dir brute-force) |
| `--resume` | Resume from last checkpoint |
| `--ai <provider>` | AI provider: `opencode` (default), `disabled` |
| `--list-tools` | List all available tools |
| `--category <cat>` | Filter --list-tools by category |
| `--web` | Launch web dashboard |
| `--setup-keys` | Interactive API key setup wizard |
| `--only-missing` | Only run tools with newly configured API keys |
| `--verbose` | Detailed output |
| `--threads <n>` | Thread count for parallel tasks (default: 50) |

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| **Files not saving to host** | Use `-v $(pwd)/output:/opt/ultimate-recon/workspaces` when running Docker |
| **AI prompt hangs** | Use `--ai disabled` to skip interactive prompts |
| **Docker build fails** | Ensure you're in the project root directory with a stable internet connection |
| **No results for a phase** | Some tools require API keys — run `--setup-keys` or check `.env` |
| **"Tool not found"** | The tool might have failed during build — check `docker build` output |
| **Out of disk space** | Clean Docker cache: `docker system prune` |
| **Web UI not working** | Ensure you mounted the workspaces directory: `-v $(pwd)/output:/opt/ultimate-recon/workspaces` |

---

## 🏗️ Architecture

```
ultimate-recon/
├── Dockerfile              # Multi-stage build (builder + final)
├── run.sh                  # Entry point — auto-detects Docker vs native
├── setup.sh                # Native dependency installer
├── docker-compose.yml      # Docker Compose configuration
├── config/
│   ├── settings.yaml       # Phase-specific tool configuration
│   ├── ai-providers.yaml   # AI provider settings
│   └── prompts/            # AI analysis prompts per phase
├── src/
│   ├── orchestrator.py     # Main pipeline controller
│   ├── ai_engine.py        # AI provider system
│   ├── analyzer.py         # Rule-based analysis + fallbacks
│   ├── tool_registry.py    # 61+ tool definitions
│   ├── checker.py          # Environment health checks
│   ├── database.py         # SQLite result storage
│   └── modules/
│       ├── phase1_recon.py      # Asset discovery
│       ├── phase2_live_urls.py  # Live hosts + URLs
│       ├── phase3_deep_recon.py # Parameters, JS, ports, dirs
│       ├── phase4_vulns.py      # Vulnerability testing
│       └── phase5_report.py     # HTML report generation
├── web-ui/
│   ├── app.py              # Flask web dashboard
│   ├── templates/          # HTML templates
│   └── static/             # Static assets
└── wordlists/
    └── resolvers.txt       # DNS resolvers for brute-force
```

---

## 🧪 Testing

```bash
python3 -m pytest src/tests/ -v
```

---

## 📄 License

MIT — For authorized security testing only.

---

## 🙏 Credits

- Based on the [Recon to Master](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0) checklist by [coffinxp](https://github.com/coffinxp)
- Powered by [ProjectDiscovery](https://projectdiscovery.io) tools, [tomnomnom](https://github.com/tomnomnom) utilities, and the security research community
- Built with ❤️ for bug bounty hunters and security researchers

---

<div align="center">

**Found this useful? ⭐ Star the repo!**

[Report Bug](https://github.com/ankitsingh015/ultimate-recon/issues) · [Request Feature](https://github.com/ankitsingh015/ultimate-recon/issues)

</div>
