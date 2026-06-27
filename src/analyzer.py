import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

class ReconAnalyzer:
    def __init__(self, output_dir: str, target: str, ai_engine=None):
        self.output_dir = Path(output_dir)
        self.target = target
        self.ai_engine = ai_engine
        self.analysis_dir = self.output_dir / "analysis"
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self.chat_file = self.output_dir / "chat.jsonl"
        self.findings = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phases": {},
            "highlights": [],
            "chained_attacks": [],
            "recommendations": []
        }

    def analyze_phase(self, phase_num: int, phase_data: dict) -> dict:
        if self.ai_engine:
            try:
                ai_analysis = self.ai_engine.analyze_phase(phase_num, phase_data, self.output_dir)
                phase_data["_ai_analysis"] = ai_analysis
                self.save_analysis(f"phase{phase_num}", ai_analysis)
                return ai_analysis
            except Exception as e:
                print(f"  [!] AI analysis failed: {e}. Using rule-based fallback.")

        fallbacks = {
            1: self._analyze_phase1,
            2: self._analyze_phase2,
            3: self._analyze_phase3,
            4: self._analyze_phase4,
        }
        analyzer = fallbacks.get(phase_num, self._analyze_phase1)
        result = analyzer(phase_data)
        self.save_analysis(f"phase{phase_num}", result)
        return result

    def _categorize_subdomain(self, subdomain: str) -> Optional[str]:
        patterns = {
            "admin": r"\b(admin|administrator|dashboard|panel|cpanel|whm)\b",
            "dev": r"\b(dev|development|staging|test|testing|qa|beta|uat|sandbox)\b",
            "api": r"\b(api|graphql|swagger|docs|developer|devportal)\b",
            "auth": r"\b(login|signin|auth|sso|oauth|saml|ldap)\b",
            "internal": r"\b(internal|intranet|corp|corporate|employee|private)\b",
            "cloud": r"\b(s3|bucket|storage|cdn|cloud|aws|azure|gcp)\b",
            "monitoring": r"\b(monitor|grafana|prometheus|kibana|jenkins|jira|confluence)\b",
            "database": r"\b(db|database|mysql|postgres|redis|mongo|sql|elastic)\b",
            "backup": r"\b(backup|old|deprecated|archive|legacy)\b",
            "mail": r"\b(mail|email|smtp|imap|pop3|exchange|webmail)\b",
        }
        for category, pattern in patterns.items():
            if re.search(pattern, subdomain, re.IGNORECASE):
                return category
        return None

    def _interesting_url(self, url: str) -> Optional[str]:
        patterns = {
            "login": r"\b(login|signin|signup|register|auth)\b",
            "reset": r"\b(forgot|reset|recover|password)\b",
            "upload": r"\b(upload|file|import|attach)\b",
            "download": r"\b(download|export|backup|dump)\b",
            "api": r"\b(api|v1|v2|graphql|rest|swagger|openapi)\b",
            "config": r"\b(config|conf|settings|setup|install|admin)\b",
            "sensitive": r"\b(server-status|server-info|phpinfo|info|debug)\b",
        }
        for category, pattern in patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                return category
        return None

    def _sensitive_extension(self, url: str) -> Optional[str]:
        sensitive_exts = [
            ".sql", ".db", ".sqlite", ".mdb", ".bak", ".backup", ".old",
            ".env", ".git", ".svn", ".DS_Store", ".htaccess", ".htpasswd",
            ".pem", ".key", ".crt", ".csr", ".p12", ".pfx",
            ".log", ".txt", ".conf", ".config", ".yml", ".yaml", ".ini",
            ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
            ".xls", ".xlsx", ".csv", ".pdf", ".doc", ".docx",
        ]
        for ext in sensitive_exts:
            if url.lower().endswith(ext):
                return ext
        return None

    def _tech_alerts(self, tech: str, version: str) -> list:
        alerts = []
        tl = tech.lower()
        if "wordpress" in tl:
            alerts.append("CMS detected: WordPress — run WPScan for plugin/theme vulns")
        if "drupal" in tl:
            alerts.append("CMS detected: Drupal — check for known CVEs")
        if "joomla" in tl:
            alerts.append("CMS detected: Joomla — check for known CVEs")
        if "apache" in tl and version:
            if version.startswith("2.4.49"):
                alerts.append(f"Apache {version} — CVE-2021-41773 Path Traversal")
            elif version.startswith("2.4.50"):
                alerts.append(f"Apache {version} — CVE-2021-42013 Path Traversal")
        if "php" in tl and version:
            parts = version.split(".")[:2]
            if len(parts) == 2:
                try:
                    major, minor = int(parts[0]), int(parts[1])
                    if major < 7 or (major == 7 and minor < 4):
                        alerts.append(f"PHP {version} is outdated")
                except ValueError:
                    pass
        return alerts

    def _analyze_phase1(self, phase_data: dict) -> dict:
        subdomains = phase_data.get("subdomains", [])
        ips = phase_data.get("ips", [])
        tech_stack = phase_data.get("tech_stack", {})

        interesting = {}
        for sub in subdomains:
            cat = self._categorize_subdomain(sub)
            if cat:
                interesting.setdefault(cat, []).append(sub)

        tech_alerts = []
        for tech, version in tech_stack.items():
            alerts = self._tech_alerts(tech, version)
            tech_alerts.extend(alerts)

        recs = []
        if interesting.get("admin"):
            recs.append(f"{len(interesting['admin'])} admin panels found — test for auth bypass, default creds")
        if interesting.get("dev"):
            recs.append(f"{len(interesting['dev'])} dev/staging hosts — likely less secure, prioritize")
        if interesting.get("api"):
            recs.append(f"{len(interesting['api'])} API endpoints — test for IDOR, rate limiting, auth issues")
        if interesting.get("cloud"):
            recs.append(f"{len(interesting['cloud'])} cloud assets — check for public buckets")
        if interesting.get("database"):
            recs.append(f"{len(interesting['database'])} database-related hosts — check for exposed ports")
        if interesting.get("mail"):
            recs.append(f"{len(interesting['mail'])} mail servers — check for open relay, spoofing")
        if interesting.get("monitoring"):
            recs.append(f"{len(interesting['monitoring'])} monitoring tools — check for default creds, CVEs")
        if interesting.get("backup"):
            recs.append(f"{len(interesting['backup'])} backup/old hosts — likely less maintained, good targets")

        recs.extend(tech_alerts)

        if len(subdomains) > 1000:
            recs.append(f"Large attack surface ({len(subdomains)} subdomains) — consider scope narrowing")
        if ips:
            recs.append(f"{len(ips)} IPs discovered — run port scanning on all ranges")

        return {
            "phase": 1,
            "name": "Asset Discovery",
            "interesting_hosts": interesting,
            "tech_alerts": tech_alerts,
            "summary": {"subdomains": len(subdomains), "ips": len(ips)},
            "recommendations": recs[:10],
            "phase2_config": {
                "prioritize_hosts": list(dict.fromkeys(
                    interesting.get("admin", [])[:5] +
                    interesting.get("dev", [])[:5] +
                    interesting.get("api", [])[:3]
                ))
            }
        }

    def _analyze_phase2(self, phase_data: dict) -> dict:
        urls = phase_data.get("urls", [])
        live_hosts = phase_data.get("live_hosts", [])
        tech_stack = phase_data.get("tech_stack", {})

        categorized = {}
        sensitive_files = []
        for url in urls:
            cat = self._interesting_url(url)
            if cat:
                if cat not in categorized:
                    categorized[cat] = []
                if len(categorized[cat]) < 10:
                    categorized[cat].append(url)
            ext = self._sensitive_extension(url)
            if ext:
                sensitive_files.append(url)

        recs = []
        if categorized.get("login"):
            recs.append(f"{len(categorized['login'])} login pages — test for auth bypass, cred stuffing")
        if categorized.get("upload"):
            recs.append(f"{len(categorized['upload'])} upload endpoints — test for unrestricted file upload")
        if categorized.get("api"):
            recs.append(f"{len(categorized['api'])} API endpoints — test for IDOR, rate limiting")
        if sensitive_files:
            recs.append(f"{len(sensitive_files)} sensitive files — check for info disclosure")
        if live_hosts and len(live_hosts) > 50:
            recs.append(f"{len(live_hosts)} live hosts — continue with parameter analysis")

        return {
            "phase": 2,
            "name": "Live Hosts & URL Collection",
            "interesting_urls": categorized,
            "sensitive_files": sensitive_files[:50],
            "summary": {"live": len(live_hosts), "urls": len(urls), "sensitive": len(sensitive_files)},
            "recommendations": recs[:10],
            "phase3_config": {
                "prioritize_urls": list(dict.fromkeys(
                    categorized.get("login", [])[:5] +
                    categorized.get("api", [])[:5] +
                    categorized.get("upload", [])[:3]
                ))
            }
        }

    def _analyze_phase3(self, phase_data: dict) -> dict:
        params = phase_data.get("params", {})
        ports = phase_data.get("ports", [])
        js_secrets = phase_data.get("js_secrets", [])

        recs = []
        param_opps = []
        for vtype, urls_list in params.items():
            if urls_list:
                param_opps.append({"type": vtype, "count": len(urls_list)})
                if vtype in ("sqli", "xss", "lfi", "ssrf"):
                    recs.append(f"{len(urls_list)} {vtype.upper()} params found — prioritize testing")

        unusual_ports = [p for p in ports if p.get("port", 0) not in (80, 443, 8080, 8443, 22, 21)]
        if unusual_ports:
            recs.append(f"Unusual ports: {[p['port'] for p in unusual_ports[:5]]} — investigate services")

        if js_secrets:
            recs.append(f"{len(js_secrets)} potential secrets in JS — validate with targeted testing")

        return {
            "phase": 3,
            "name": "Deep Recon & Parameter Analysis",
            "param_opportunities": param_opps,
            "summary": {"params": sum(len(v) for v in params.values()), "ports": len(ports), "secrets": len(js_secrets)},
            "recommendations": recs[:10],
            "phase4_config": {
                "prioritize_vulns": [p["type"] for p in param_opps if p["count"] > 0][:5],
                "specific_urls": []
            }
        }

    def _analyze_phase4(self, phase_data: dict) -> dict:
        vulns = phase_data.get("vulnerabilities", [])
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in by_severity:
                by_severity[sev].append(v)

        recs = []
        if by_severity["critical"]:
            recs.append(f"{len(by_severity['critical'])} CRITICAL — report immediately")
        if by_severity["high"]:
            recs.append(f"{len(by_severity['high'])} HIGH — prioritize for reporting")
        if by_severity["medium"]:
            recs.append(f"{len(by_severity['medium'])} MEDIUM — investigate further")

        chains = []
        xss_found = [v for v in vulns if "xss" in v.get("type", "").lower()]
        cors_found = [v for v in vulns if "cors" in v.get("type", "").lower()]
        if xss_found and cors_found:
            chains.append({
                "name": "XSS + CORS → Account Takeover",
                "severity": "critical",
                "steps": [
                    f"XSS at: {xss_found[0].get('url', '?')}",
                    f"CORS misconfig on: {cors_found[0].get('url', '?')}",
                    "Chain: XSS executes fetch() cross-origin to exfiltrate data"
                ]
            })

        ssrf_found = [v for v in vulns if "ssrf" in v.get("type", "").lower()]
        if ssrf_found:
            chains.append({
                "name": "SSRF → Cloud Metadata → Credential Theft",
                "severity": "critical",
                "steps": [
                    f"SSRF at: {ssrf_found[0].get('url', '?')}",
                    "Test: http://169.254.169.254/latest/meta-data/",
                    "Impact: Full cloud account compromise"
                ]
            })

        return {
            "phase": 4,
            "name": "Vulnerability Discovery",
            "confirmed_vulns": by_severity,
            "potential_chains": chains,
            "summary": {s: len(v) for s, v in by_severity.items() if v},
            "recommendations": recs[:10],
        }

    def chain_vulnerabilities(self, all_findings: list, tech_stack: dict) -> list:
        if self.ai_engine:
            try:
                return self.ai_engine.chain_vulnerabilities(all_findings, tech_stack, self.output_dir)
            except Exception:
                pass

        chains = []
        vuln_types = [v.get("type", "").lower() for v in all_findings]

        if "xss" in str(vuln_types) and "cors" in str(vuln_types):
            chains.append({
                "name": "XSS + CORS → Account Takeover",
                "severity": "critical",
                "description": "XSS on a CORS-misconfigured domain can leak data cross-origin",
                "steps": ["Execute XSS payload", "Use fetch() to read cross-origin responses", "Exfiltrate to attacker server"],
                "impact": "Full account takeover"
            })

        if "ssrf" in str(vuln_types):
            chains.append({
                "name": "SSRF → Cloud Metadata Access",
                "severity": "critical",
                "description": "SSRF can access cloud provider metadata endpoints",
                "steps": ["Identify SSRF-vulnerable parameter", "Target http://169.254.169.254/latest/meta-data/", "Extract IAM credentials"],
                "impact": "Cloud account compromise"
            })

        if "lfi" in str(vuln_types):
            chains.append({
                "name": "LFI → RCE via Log Poisoning",
                "severity": "high",
                "description": "LFI combined with log injection can lead to remote code execution",
                "steps": ["Identify writable log path via LFI", "Inject PHP code into User-Agent header", "Access log file via LFI to execute code"],
                "impact": "Remote code execution on server"
            })

        if "open redirect" in str(vuln_types) and "xss" in str(vuln_types):
            chains.append({
                "name": "Open Redirect + XSS → Phishing Chain",
                "severity": "high",
                "description": "Open redirect can make XSS phishing more convincing",
                "steps": ["Create phishing URL using open redirect", "Chain with XSS payload", "Bypass URL scanners"],
                "impact": "Credential theft via phishing"
            })

        return chains

    def generate_highlights(self, phases: dict) -> list:
        highlights = []
        for phase_name, phase_data in phases.items():
            analysis = phase_data if isinstance(phase_data, dict) else {}
            recs = analysis.get("recommendations", [])
            for rec in recs:
                if any(w in rec.lower() for w in ["critical", "high", "urgent", "takeover", "secret"]):
                    highlights.append(f"[{phase_name}] {rec}")

            vulns = analysis.get("confirmed_vulns", {})
            for sev in ["critical", "high"]:
                for v in vulns.get(sev, []):
                    highlights.append(f"[{sev.upper()}] {v.get('type', '?')} at {v.get('url', '?')}")

        return highlights[:50]

    def save_analysis(self, name: str, analysis: dict):
        self.findings["phases"][name] = analysis

        json_path = self.analysis_dir / f"{name}-analysis.json"
        with open(json_path, "w") as f:
            json.dump(analysis, f, indent=2)

        md_path = self.analysis_dir / f"{name}-summary.txt"
        with open(md_path, "w") as f:
            f.write(f"=== {name.upper()} ANALYSIS ===\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n\n")

            recs = analysis.get("recommendations", [])
            if recs:
                f.write("Recommendations:\n")
                for r in recs:
                    f.write(f"  → {r}\n")
                f.write("\n")

            interesting = analysis.get("interesting_hosts", {})
            if interesting:
                f.write("Interesting Subdomains:\n")
                for cat, subs in interesting.items():
                    f.write(f"  [{cat.upper()}] {len(subs)} found\n")
                    for s in subs[:5]:
                        f.write(f"    - {s}\n")
                f.write("\n")

            chains = analysis.get("potential_chains", [])
            if chains:
                f.write("Potential Attack Chains:\n")
                for c in chains:
                    f.write(f"  [CHAIN] {c['name']} ({c.get('severity', '?')})\n")
                    for step in c.get("steps", []):
                        f.write(f"    - {step}\n")
                f.write("\n")

    def save_highlights(self, highlights: list):
        fp = self.analysis_dir / "highlights.txt"
        with open(fp, "w") as f:
            f.write(f"=== HIGHLIGHTS for {self.target} ===\n")
            f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
            for h in highlights:
                f.write(f"  {h}\n")
        return str(fp)

    def finalize(self):
        self.findings["highlights"] = self.generate_highlights(self.findings["phases"])
        self.save_highlights(self.findings["highlights"])

        fp = self.analysis_dir / "full-analysis.json"
        with open(fp, "w") as f:
            json.dump(self.findings, f, indent=2)

        return str(fp)
