# Ultimate Recon

**61 bug bounty recon tools, 5-phase automated pipeline, AI-powered analysis.**

---

## Docker (Recommended)

```bash
git clone https://github.com/ankitsingh015/ultimate-recon.git
cd ultimate-recon

docker build -t ultimate-recon .

docker run ultimate-recon example.com
docker run ultimate-recon example.com --stealth
docker run ultimate-recon example.com --phase 1,2
docker run ultimate-recon example.com --tool subfinder
docker run ultimate-recon --list-tools
```

## Native

```bash
./setup.sh
./run.sh example.com
./run.sh example.com --tool subfinder --output ./results
./run.sh --list-tools
```

---

## Usage

### Full Pipeline

Run all 5 phases against a target — subdomain enumeration → URL crawling → parameter analysis → vulnerability testing → HTML report.

```bash
docker run ultimate-recon example.com
```

Open `output/example.com/report.html` when done.

### Single Tool Mode

Run any of the 61 tools individually — output saved, AI analysis run on results.

```bash
docker run ultimate-recon example.com --tool subfinder
docker run ultimate-recon example.com --tool httpx --output /results
docker run ultimate-recon example.com --tool nuclei
```

### List Available Tools

```bash
docker run ultimate-recon --list-tools
docker run ultimate-recon --list-tools --category subdomain
docker run ultimate-recon --list-tools --category vuln
```

---

## Pipeline

| Phase | What It Does |
|-------|-------------|
| 0 | Environment check — tools, API keys, disk space |
| 1 | **Asset Discovery** — 15+ subdomain tools in parallel, IP/ASN mapping |
| 2 | **Live Hosts + URLs** — HTTP probing, crawling, tech detection, screenshots |
| 3 | **Deep Recon** — Parameter extraction, JS secrets, port scanning, directory brute-force |
| 4 | **Vulnerability Testing** — SQLi, XSS, LFI, SSRF, CORS, Open Redirect, subdomain takeover, git leaks, cloud assets, nuclei |
| 5 | **Report Generation** — HTML report with findings, evidence, attack chains |

Each phase saves raw results to `all_results/` and AI analysis to `analysis/`.

---

## All 61 Tools

| Category | Tools |
|---|---|
| **Subdomain** (18) | subfinder, assetfinder, findomain, amass, crt.sh, wayback, urlscan, hackertarget, commoncrawl, virustotal, github-subdomains, shosubgo, chaos, dnsrecon, haktrails, alterx, shuffledns, dnsx |
| **URL** (6) | gau, waymore, katana, gospider, hakrawler, urlfinder |
| **Param** (6) | gf sqli, gf xss, gf lfi, gf ssrf, gf redirect, arjun |
| **JS** (4) | subjs, getJS, linkfinder, secretfinder |
| **Port** (4) | naabu, nmap, rustscan, masscan |
| **Dir** (2) | dirsearch, ffuf |
| **Tech** (2) | whatweb, wafw00f |
| **Vuln** (8) | nuclei, sqlmap, dalfox, corsy, subzy, wpscan, sstimap, commix |
| **Cloud** (2) | s3scanner, cloud_enum |
| **Git** (2) | gitdumper, nuclei git |
| **IP** (1) | asnmap |
| **Screenshot** (2) | gowitness, aquatone |
| **Live Host** (1) | httpx |
| **Fuzz** (1) | ffuf |
| **Util** (2) | qsreplace, uro |

---

## API Keys

Optional — the tool works without them, only key-dependent sources are skipped.

```
cp .env.example .env   # Edit .env with your keys
```

Supported: `GITHUB_TOKEN`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `CHAOS_API_KEY`, `SECURITYTRAILS_API_KEY`, `URLSCAN_API_KEY`

---

## Output

```
output/example.com/
├── all_results/        ← Every tool's raw output (false positives included)
├── analysis/           ← AI findings + recommendations
├── screenshots/
├── vulns/
└── report.html        ← Full HTML report
```

---

## Options

```
--stealth              Skip aggressive scans (port scan, dir brute)
--phase 1,2            Run specific phases only
--resume               Resume from last checkpoint
--tool <name>          Run a single tool
--output / --o         Custom output directory
--list-tools           List all available tools
--category <cat>       Filter --list-tools by category
--setup-keys           Interactive API key wizard
```

---

## Credits

Based on the [Recon to Master](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0) checklist by [coffinxp](https://github.com/coffinxp).

For authorized security testing only.
