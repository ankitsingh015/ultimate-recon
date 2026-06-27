# Ultimate Recon

Complete Bug Bounty Reconnaissance Toolkit — 61 tools, automated 5-phase pipeline, AI-powered analysis.

---

## Quick Start

```bash
# Docker (recommended — all 61 tools pre-installed)
docker build -t ultimate-recon .
docker run -v $(pwd)/output:/opt/ultimate-recon/output ultimate-recon example.com
open output/example.com/report.html

# Native (power users)
./setup.sh
./run.sh example.com

# Single tool + AI analysis
./run.sh example.com --tool subfinder --output ~/my-results

# List available tools
./run.sh --list-tools
./run.sh --list-tools --category subdomain
```

---

## API Key Security

### Setup (takes 30 seconds)

```bash
# Option A: Interactive wizard
./run.sh --setup-keys

# Option B: Manual
cp .env.example .env
nano .env       # Add your keys
```

### Security Model

```
Load priority (highest wins):
  1. .env file               ← gitignored, never committed
  2. config/api-keys.yaml     ← gitignored, never committed
  3. Environment variables    ← OS-level (export SHODAN_API_KEY=xxx)

Key scrubbing:
  API keys are REDACTED from all console output and logs.
  Nothing containing your keys is ever written to disk.
```

### What gets committed vs not

| File | Committed? | Purpose |
|---|---|---|
| `.env.example` | ✅ Yes | Template with empty keys and URLs to get them |
| `config/api-keys.example.yaml` | ✅ Yes | YAML template |
| `.env` | ❌ **Never** (in .gitignore) | Your actual API keys |
| `config/api-keys.yaml` | ❌ **Never** (in .gitignore) | Your actual API keys |
| `output/` | ❌ **Never** (in .gitignore) | All recon results |

---

## Pipeline: How AI Analysis Works

```
Phase 1: 15+ tools run in parallel → saves ALL raw results
         ↓
🧠 AI Analysis:
   - Categorizes subdomains (admin, dev, api, cloud...)
   - Detects technologies + version-specific CVEs
   - Saves structured JSON + human-readable summary
   → "Found 12 dev subdomains. WordPress 5.8 has known vulns."
         ↓
Phase 2: httpx + crawlers + screenshots → AI analysis
         ↓
Phase 3: GF params + JS secrets + ports → AI analysis
         ↓
Phase 4: 12 vuln scanners in parallel → AI chains attacks
         ↓
Phase 5: HTML report with chained attack paths
```

Each phase STOPS after completion — you or OpenCode can read the analysis and configure the next phase intelligently.

---

## Single Tool Mode

```bash
# Run any tool standalone + get AI analysis on its output
./run.sh example.com --tool subfinder
./run.sh example.com --tool httpx --output ~/custom-dir
./run.sh example.com --tool nuclei
./run.sh example.com --tool whatweb --output ./results
```

Every tool output goes to `all_results/`, AI analysis to `analysis/`.

---

## All 61 Tools

| Category | Tools |
|---|---|
| **Subdomain** (18) | subfinder, assetfinder, findomain, amass, crt.sh, wayback, urlscan, hackertarget, commoncrawl, virustotal, github-subdomains, shosubgo, chaos, dnsrecon, haktrails, alterx, shuffledns, dnsx |
| **IP** (1) | asnmap |
| **Live Host** (1) | httpx |
| **URL** (6) | gau, waymore, katana, gospider, hakrawler, urlfinder |
| **Tech** (2) | whatweb, wafw00f |
| **Param** (6) | gf sqli, gf xss, gf lfi, gf ssrf, gf redirect, arjun |
| **JS** (4) | subjs, getJS, linkfinder, secretfinder |
| **Port** (4) | naabu, nmap, rustscan, masscan |
| **Dir** (2) | dirsearch, ffuf |
| **Screenshot** (2) | gowitness, aquatone |
| **Vuln** (8) | nuclei, sqlmap, dalfox, corsy, subzy, wpscan, sstimap, commix |
| **Cloud** (2) | s3scanner, cloud_enum |
| **Git** (2) | gitdumper, nuclei git |
| **Fuzz** (1) | ffuf |
| **Util** (2) | qsreplace, uro |

---

## Output Structure

```
output/example.com/
├── all_results/              ← EVERY raw output (false positives included)
│   ├── all-subdomains.txt
│   ├── all-urls.txt
│   ├── all-params.txt
│   ├── all-vulns.txt
│   ├── all-everything.txt    ← Mega file with ALL tool outputs
│   └── ... (every tool's raw output)
├── analysis/                 ← AI analysis (separate from raw data)
│   ├── phase1-analysis.json
│   ├── phase1-summary.txt
│   ├── highlights.txt
│   └── full-analysis.json
├── screenshots/
├── vulns/
├── recon.db                  ← SQLite (all findings searchable)
└── report.html               ← Full HTML report
```

---

## Options

```bash
./run.sh example.com                  # Full 5-phase pipeline
./run.sh example.com --stealth        # Skip aggressive scans
./run.sh example.com --phase 1,2      # Run specific phases
./run.sh example.com --resume         # Resume from checkpoint
./run.sh example.com --tool nmap      # Single tool mode
./run.sh --setup-keys                 # API key wizard
./run.sh --list-tools                 # List all tools
```

---

## Security Best Practices

1. **Never commit API keys** — `.env` and `config/api-keys.yaml` are in `.gitignore`
2. **Use `.env` over YAML** — simpler, more standard, harder to accidentally commit
3. **Rotate keys regularly** — especially if you suspect any logs were shared
4. **Run in Docker** — isolates the toolkit from your main system
5. **Scope your recon** — only test targets you have written permission to test

---

## Credits

Based on the [Recon to Master](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0) checklist by [coffinxp](https://github.com/coffinxp).

## License

For educational and authorized security testing only.
