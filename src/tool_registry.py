import shlex
from typing import Dict, List, Optional, Callable

class ToolRegistry:
    TOOLS: Dict[str, dict] = {}

    @classmethod
    def register(cls, name: str, category: str, description: str, cmd_template: str,
                 output_ext: str = ".txt", needs_api: str = None,
                 timeout: int = 300, phase: int = None):
        cls.TOOLS[name] = {
            "name": name,
            "category": category,
            "description": description,
            "cmd_template": cmd_template,
            "output_ext": output_ext,
            "needs_api": needs_api,
            "timeout": timeout,
            "phase": phase,
        }

    @classmethod
    def get(cls, name: str) -> Optional[dict]:
        return cls.TOOLS.get(name)

    @classmethod
    def list_by_category(cls, category: str = None) -> List[dict]:
        if category:
            return [t for t in cls.TOOLS.values() if t["category"] == category]
        return list(cls.TOOLS.values())

    @classmethod
    def categories(cls) -> Dict[str, List[dict]]:
        cats = {}
        for t in cls.TOOLS.values():
            cats.setdefault(t["category"], []).append(t)
        return cats

    @classmethod
    def build_cmd(cls, name: str, target: str, output_path, api_keys: dict = None) -> Optional[str]:
        tool = cls.get(name)
        if not tool:
            return None

        from pathlib import Path
        if isinstance(output_path, str):
            output_path = Path(output_path)

        cmd = tool["cmd_template"]
        key = (api_keys or {}).get(tool.get("needs_api", ""), "") if tool.get("needs_api") else ""
        replacements = {
            "{target}": target,
            "{output}": str(output_path),
            "{output_dir}": str(output_path.parent),
            "{api_key}": key,
            "{api}": key,
        }

        for k, v in replacements.items():
            cmd = cmd.replace(k, str(v))

        return cmd


ToolRegistry.register("subfinder", "subdomain", "Passive subdomain enumeration via multiple sources",
    "subfinder -d {target} -all -recursive -o {output} 2>/dev/null", phase=1)

ToolRegistry.register("assetfinder", "subdomain", "Passive subdomain discovery from various sources",
    "assetfinder --subs-only {target} 2>/dev/null > {output}", phase=1)

ToolRegistry.register("findomain", "subdomain", "Fast subdomain discovery using APIs",
    "findomain -t {target} -q 2>/dev/null > {output}", phase=1)

ToolRegistry.register("amass_passive", "subdomain", "OWASP Amass passive subdomain enumeration",
    "amass enum -passive -d {target} -timeout 5 -o {output} 2>/dev/null", timeout=600, phase=1)

ToolRegistry.register("crtsh", "subdomain", "Certificate Transparency log subdomain extraction",
    "curl -s 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | grep -Po '(\\w+\\.\\w+\\.\\w+)$' | sort -u > {output}", phase=1)

ToolRegistry.register("wayback", "subdomain", "Wayback Machine historical subdomain extraction",
    "curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey' 2>/dev/null | sort -u | sed -e 's_https*://__' -e 's/\\/.*//' -e 's/:.*//' -e 's/^www\\.//' | sort -u > {output}", phase=1)

ToolRegistry.register("urlscan", "subdomain", "urlscan.io subdomain discovery",
    "curl -s 'https://urlscan.io/api/v1/search/?q=domain:{target}&size=100' 2>/dev/null | jq -r '.results[].page.domain' 2>/dev/null | sort -u > {output}", phase=1)

ToolRegistry.register("hackertarget", "subdomain", "HackerTarget passive DNS enumeration",
    "curl -s 'https://api.hackertarget.com/hostsearch/?q={target}' 2>/dev/null | cut -d',' -f1 | sort -u > {output}", phase=1)

ToolRegistry.register("commoncrawl", "subdomain", "CommonCrawl index subdomain extraction",
    "curl -s 'https://index.commoncrawl.org/CC-MAIN-2024-22-index?url=*.{target}&output=json' 2>/dev/null | jq -r '.url' 2>/dev/null | sed -e 's_https*://__' -e 's/\\/.*//g' | sort -u > {output}", phase=1)

ToolRegistry.register("virustotal", "subdomain", "VirusTotal domain siblings",
    "curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={target}' 2>/dev/null | jq -r '.domain_siblings[]' 2>/dev/null | sort -u > {output}",
    needs_api="virustotal", phase=1)

ToolRegistry.register("github_subdomains", "subdomain", "GitHub subdomain scraping",
    "github-subdomains -d {target} -t {api_key} 2>/dev/null > {output}",
    needs_api="github", phase=1)

ToolRegistry.register("shosubgo", "subdomain", "Shodan-powered subdomain finder",
    "shosubgo -d {target} -s {api_key} 2>/dev/null > {output}",
    needs_api="shodan", phase=1)

ToolRegistry.register("chaos", "subdomain", "ProjectDiscovery Chaos subdomains",
    "chaos -d {target} -silent 2>/dev/null > {output}",
    needs_api="chaos", phase=1)

ToolRegistry.register("dnsrecon", "subdomain", "DNS reconnaissance",
    "dnsrecon -d {target} -t std 2>/dev/null | grep -oP '([a-zA-Z0-9.-]+\\.{target})' | sort -u > {output}", phase=1)

ToolRegistry.register("haktrails", "subdomain", "SecurityTrails subdomain lookup",
    "haktrails {target} 2>/dev/null | sort -u > {output}",
    needs_api="securitytrails", phase=1)

ToolRegistry.register("alterx", "subdomain", "Subdomain permutation generator",
    "cat {output_dir}/../all-subdomains.txt 2>/dev/null | alterx -enrich 2>/dev/null | dnsx -silent -a -resp-only 2>/dev/null | sort -u > {output}", timeout=600, phase=1)

ToolRegistry.register("shuffledns", "subdomain", "Subdomain brute-force with wordlist",
    "shuffledns -d {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent 2>/dev/null | sort -u > {output}", timeout=600, phase=1)

ToolRegistry.register("dnsx", "subdomain", "DNS resolution and validation",
    "cat {output_dir}/../all-subdomains.txt 2>/dev/null | sort -u | dnsx -silent -a -resp-only 2>/dev/null | sort -u > {output}", timeout=300, phase=1)

ToolRegistry.register("asnmap", "ip", "ASN to IP range mapping",
    "asnmap -d {target} 2>/dev/null | dnsx -silent -resp-only 2>/dev/null | sort -u > {output}", phase=1)

ToolRegistry.register("httpx", "live_host", "HTTP probing and tech detection",
    "httpx -silent -l {output_dir}/../all-subdomains.txt -ports 80,443,8080,8000,8888,8443,3000,5000 -status-code -title -tech-detect -threads 50 -o {output} 2>/dev/null", timeout=600, phase=2)

ToolRegistry.register("gau", "url", "Get All URLs from archives",
    "gau {target} --mc 200 --threads 50 2>/dev/null | sort -u > {output}", phase=2)

ToolRegistry.register("waymore", "url", "Wayback Machine URL collector (enhanced)",
    "waymore -i {target} -mode U -oU {output} 2>/dev/null", phase=2)

ToolRegistry.register("katana", "url", "Web crawler for endpoint discovery",
    "katana -u {target} -silent -d 2 -kf -jc 2>/dev/null | sort -u > {output}", phase=2)

ToolRegistry.register("gospider", "url", "Lightweight web spider",
    "gospider -s https://{target} -t 3 -d 1 --sitemap --robots -q 2>/dev/null | tee {output}", timeout=600, phase=2)

ToolRegistry.register("hakrawler", "url", "Lightweight web crawler",
    "echo {target} | hakrawler -subs -u -t 50 2>/dev/null | sort -u > {output}", phase=2)

ToolRegistry.register("urlfinder", "url", "URL discovery tool",
    "urlfinder -d {target} -silent 2>/dev/null | sort -u > {output}", phase=2)

ToolRegistry.register("whatweb", "tech", "Website technology fingerprinting",
    "whatweb https://{target} -a 3 --log-verbose={output} 2>/dev/null", phase=2)

ToolRegistry.register("wafw00f", "tech", "WAF detection",
    "wafw00f https://{target} 2>/dev/null | tee {output}", phase=2)

ToolRegistry.register("gf_sqli", "param", "GF filter for SQL injection patterns",
    "gf sqli {output_dir}/../all-urls.txt 2>/dev/null | uro 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("gf_xss", "param", "GF filter for XSS patterns",
    "gf xss {output_dir}/../all-urls.txt 2>/dev/null | uro 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("gf_lfi", "param", "GF filter for LFI patterns",
    "gf lfi {output_dir}/../all-urls.txt 2>/dev/null | uro 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("gf_ssrf", "param", "GF filter for SSRF patterns",
    "gf ssrf {output_dir}/../all-urls.txt 2>/dev/null | uro 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("gf_redirect", "param", "GF filter for Open Redirect patterns",
    "gf redirect {output_dir}/../all-urls.txt 2>/dev/null | uro 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("arjun", "param", "Hidden parameter discovery",
    "arjun -u https://{target} -oT {output} --passive -m GET,POST --rate-limit 10 -t 10 2>/dev/null", timeout=600, phase=3)

ToolRegistry.register("subjs", "js", "JavaScript file discovery",
    "subjs -i {output_dir}/../alive-hosts.txt 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("getJS", "js", "JavaScript file extraction tool",
    "getJS --complete --input {output_dir}/../alive-hosts.txt 2>/dev/null | sort -u > {output}", phase=3)

ToolRegistry.register("linkfinder", "js", "Endpoint extraction from JS files",
    "cat {output_dir}/../all-js-files.txt 2>/dev/null | head -20 | xargs -I@ -P5 bash -c 'python3 /opt/LinkFinder/linkfinder.py -i @ -o cli 2>/dev/null' 2>/dev/null | grep -oP 'https?://[^\"\\'<> ]+' | sort -u > {output}", timeout=600, phase=3)

ToolRegistry.register("secretfinder", "js", "Secret/key extraction from JS files",
    "cat {output_dir}/../all-js-files.txt 2>/dev/null | head -20 | xargs -I@ -P5 python3 /opt/SecretFinder/SecretFinder.py -i @ -o cli 2>/dev/null | grep -iE '(api.?key|secret|token|password|aws|bucket|slack|firebase|jwt|heroku)' | sort -u > {output}", timeout=600, phase=3)

ToolRegistry.register("naabu", "port", "Fast port scanner",
    "naabu -host {target} -silent -c 50 -o {output} 2>/dev/null", timeout=600, phase=3)

ToolRegistry.register("nmap", "port", "Full port and service scan",
    "nmap -p- --min-rate 1000 -T4 -A {target} -oN {output} 2>/dev/null", timeout=1200, phase=3)

ToolRegistry.register("rustscan", "port", "Ultra-fast port scanner",
    "rustscan -a {target} -b 1000 -- -sV 2>/dev/null | tee {output}", timeout=600, phase=3)

ToolRegistry.register("masscan", "port", "Massively parallel port scanner",
    "masscan -p0-65535 {target} --rate 100000 -oL {output} 2>/dev/null", timeout=600, phase=3)

ToolRegistry.register("dirsearch", "dir", "Directory brute-force scanner",
    "dirsearch -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,asp,aspx,jsp,html,txt -t 20 --random-agent --exclude-status=404,403 --simple-report={output} 2>/dev/null", timeout=600, phase=3)

ToolRegistry.register("ffuf_dir", "dir", "Fast directory fuzzing",
    "ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://{target}/FUZZ -fc 401,403,404 -ac -t 100 -o {output} 2>/dev/null", timeout=600, phase=3)

ToolRegistry.register("gowitness", "screenshot", "Web screenshot capture",
    "gowitness single https://{target} -P {output_dir} --disable-db 2>/dev/null",
    output_ext=".png", timeout=120, phase=2)

ToolRegistry.register("aquatone", "screenshot", "Visual recon with screenshots",
    "echo https://{target} | aquatone -out {output_dir} 2>/dev/null", timeout=300, phase=2)

ToolRegistry.register("nuclei", "vuln", "Template-based vulnerability scanner",
    "nuclei -u https://{target} -s critical,high,medium -bs 50 -c 30 -o {output} 2>/dev/null",
    timeout=600, phase=4)

ToolRegistry.register("sqlmap", "vuln", "SQL injection automation tool",
    "sqlmap -u https://{target} --batch --random-agent --level 2 --risk 2 --output-dir={output_dir} 2>/dev/null",
    timeout=1200, phase=4)

ToolRegistry.register("dalfox", "vuln", "Advanced XSS scanner",
    "dalfox url https://{target} --silence --skip-bav -o {output} 2>/dev/null",
    timeout=600, phase=4)

ToolRegistry.register("corsy", "vuln", "CORS misconfiguration scanner",
    "corsy -u https://{target} -t 10 -o {output} 2>/dev/null", timeout=300, phase=4)

ToolRegistry.register("subzy", "vuln", "Subdomain takeover checker",
    "subzy run --targets {output_dir}/../all-subdomains.txt --concurrency 100 --hide_fails --verify_ssl 2>/dev/null | tee {output}",
    timeout=600, phase=4)

ToolRegistry.register("wpscan", "vuln", "WordPress vulnerability scanner",
    "wpscan --url https://{target} --disable-tls-checks -e at,ap,u --plugins-detection aggressive 2>/dev/null | tee {output}",
    timeout=600, phase=4)

ToolRegistry.register("s3scanner", "cloud", "S3 bucket enumeration",
    "s3scanner --include-new {target} 2>/dev/null | tee {output}", timeout=300, phase=3)

ToolRegistry.register("cloud_enum", "cloud", "Multi-cloud asset enumeration",
    "cloud_enum -k {target} 2>/dev/null | tee {output}", timeout=300, phase=3)

ToolRegistry.register("gitdumper", "git", "Git repository disclosure checker",
    "curl -s 'https://{target}/.git/config' 2>/dev/null | grep -q '\\[core\\]' && echo 'VULN: {target}/.git/config exposed' > {output} || echo 'Not vulnerable' > {output}", timeout=60, phase=3)

ToolRegistry.register("nuclei_git", "git", "Nuclei git exposure scan",
    "nuclei -u https://{target} -t ~/nuclei-templates/http/exposures/ -c 30 2>/dev/null | grep -i git | tee {output}", timeout=300, phase=3)

ToolRegistry.register("sstimap", "vuln", "SSTI detection and exploitation",
    "sstimap -u https://{target} --output-file {output} 2>/dev/null", timeout=600, phase=4)

ToolRegistry.register("commix", "vuln", "Command injection detection",
    "commix -u https://{target} --output-dir={output_dir} 2>/dev/null", timeout=600, phase=4)

ToolRegistry.register("ffuf", "fuzz", "General-purpose web fuzzer",
    "ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://{target}/FUZZ -ac -t 100 -o {output} 2>/dev/null", timeout=600, phase=3)

ToolRegistry.register("qsreplace", "util", "Query string parameter replacer",
    "echo 'https://{target}/?param=test' | qsreplace 'payload' 2>/dev/null > {output}", phase=4)

ToolRegistry.register("uro", "util", "URL deduplication and normalization",
    "cat {output_dir}/../all-urls.txt 2>/dev/null | uro 2>/dev/null | sort -u > {output}", phase=3)
