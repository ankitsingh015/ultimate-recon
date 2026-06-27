import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

class ReconAnalyzer:
    def __init__(self, output_dir: str, target: str):
        self.output_dir = Path(output_dir)
        self.target = target
        self.analysis_dir = self.output_dir / "analysis"
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self.findings = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "phases": {},
            "highlights": [],
            "chained_attacks": [],
            "recommendations": []
        }

    def _interesting_subdomain(self, subdomain: str) -> Optional[str]:
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

    def _tech_vulns(self, tech: str, version: str) -> list:
        vulns = []
        tech_lower = tech.lower()
        if "wordpress" in tech_lower:
            vulns.append("CMS detected: WordPress - run WPScan for plugin/theme vulns")
        if "drupal" in tech_lower:
            vulns.append("CMS detected: Drupal - check for known CVEs")
        if "joomla" in tech_lower:
            vulns.append("CMS detected: Joomla - check for known CVEs")
        if "apache" in tech_lower and version:
            if version.startswith("2.4.49"):
                vulns.append(f"Apache {version} - CVE-2021-41773 Path Traversal")
            elif version.startswith("2.4.50"):
                vulns.append(f"Apache {version} - CVE-2021-42013 Path Traversal")
        if "nginx" in tech_lower and version:
            pass
        if "php" in tech_lower and version:
            v = version.split(".")[:2]
            if len(v) == 2:
                try:
                    major, minor = int(v[0]), int(v[1])
                    if major < 7 or (major == 7 and minor < 4):
                        vulns.append(f"PHP {version} is outdated")
                except ValueError:
                    pass
        return vulns

    def analyze_phase1(self, phase_data: dict) -> dict:
        analysis = {
            "phase": 1,
            "name": "Asset Discovery",
            "summary": {},
            "interesting_hosts": [],
            "tech_alerts": [],
            "recommendations": []
        }

        subdomains = phase_data.get("subdomains", [])
        ips = phase_data.get("ips", [])
        tech_stack = phase_data.get("tech_stack", {})

        patterns_found = {}
        for sub in subdomains:
            category = self._interesting_subdomain(sub)
            if category:
                if category not in patterns_found:
                    patterns_found[category] = []
                patterns_found[category].append(sub)

        if patterns_found:
            analysis["interesting_hosts"] = patterns_found
            for cat, subs in patterns_found.items():
                analysis["recommendations"].append(
                    f"Found {len(subs)} {cat} subdomains — prioritize for deep testing"
                )

        for tech, version in tech_stack.items():
            alerts = self._tech_vulns(tech, version)
            if alerts:
                analysis["tech_alerts"].extend(alerts)
                analysis["recommendations"].extend(alerts)

        if len(subdomains) > 1000:
            analysis["recommendations"].append(
                f"Large attack surface ({len(subdomains)} subdomains) — consider scope narrowing"
            )

        if ips:
            analysis["summary"]["ip_ranges"] = len(set(ips[:20]))
            if len(ips) > 10:
                analysis["recommendations"].append(
                    f"{len(ips)} IPs discovered — run port scanning on all ranges"
                )

        return analysis

    def analyze_phase2(self, phase_data: dict) -> dict:
        analysis = {
            "phase": 2,
            "name": "Live Hosts & URL Collection",
            "summary": {},
            "interesting_urls": [],
            "sensitive_files": [],
            "accessibility": [],
            "recommendations": []
        }

        urls = phase_data.get("urls", [])
        live_hosts = phase_data.get("live_hosts", [])

        categorized = {}
        for url in urls:
            category = self._interesting_url(url)
            if category:
                if category not in categorized:
                    categorized[category] = []
                if len(categorized[category]) < 10:
                    categorized[category].append(url)

        if categorized:
            analysis["interesting_urls"] = categorized

        sensitive = []
        for url in urls:
            ext = self._sensitive_extension(url)
            if ext:
                sensitive.append(url)
        if sensitive:
            analysis["sensitive_files"] = sensitive[:50]
            analysis["recommendations"].append(
                f"Found {len(sensitive)} potentially sensitive files — check for info disclosure"
            )

        if live_hosts:
            analysis["summary"]["live_count"] = len(live_hosts)
            if len(live_hosts) > 50:
                analysis["recommendations"].append(
                    f"{len(live_hosts)} live hosts — consider visual recon with screenshots"
                )

        return analysis

    def analyze_phase3(self, phase_data: dict) -> dict:
        analysis = {
            "phase": 3,
            "name": "Deep Recon & Parameter Analysis",
            "summary": {},
            "param_opportunities": [],
            "open_ports": [],
            "js_secrets": [],
            "recommendations": []
        }

        params = phase_data.get("params", {})
        ports = phase_data.get("ports", [])
        js_secrets = phase_data.get("js_secrets", [])

        for vuln_type, urls_list in params.items():
            if urls_list:
                count = len(urls_list)
                analysis["param_opportunities"].append({
                    "type": vuln_type,
                    "count": count,
                    "sample": urls_list[:5]
                })

        if ports:
            http_ports = [p for p in ports if p.get("port") in (80, 443, 8080, 8443)]
            unusual = [p for p in ports if p.get("port") not in (80, 443, 8080, 8443, 22)]
            analysis["open_ports"] = {
                "total": len(ports),
                "http": len(http_ports),
                "unusual": unusual[:10]
            }
            if unusual:
                analysis["recommendations"].append(
                    f"Found unusual open ports: {[p['port'] for p in unusual[:5]]} — investigate services"
                )

        if js_secrets:
            analysis["js_secrets"] = js_secrets[:20]
            analysis["recommendations"].append(
                f"Found {len(js_secrets)} potential secrets in JS files — validate and test"
            )

        return analysis

    def analyze_phase4(self, phase_data: dict) -> dict:
        analysis = {
            "phase": 4,
            "name": "Vulnerability Discovery",
            "summary": {},
            "confirmed_vulns": [],
            "potential_chains": [],
            "recommendations": []
        }

        vulns = phase_data.get("vulnerabilities", [])

        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in by_severity:
                by_severity[sev].append(v)

        analysis["summary"] = {sev: len(items) for sev, items in by_severity.items() if items}
        analysis["confirmed_vulns"] = by_severity

        if by_severity["critical"] or by_severity["high"]:
            analysis["recommendations"].append(
                f"Found {len(by_severity['critical'])} critical + {len(by_severity['high'])} high findings — prioritize remediation"
            )

        xss_found = by_severity.get("high", []) + by_severity.get("medium", [])
        xss_found = [v for v in xss_found if "xss" in v.get("type", "").lower()]

        cors_found = [v for v in vulns if "cors" in v.get("type", "").lower()]

        if xss_found and cors_found:
            chain = {
                "name": "XSS + CORS → Account Takeover",
                "description": "XSS on a CORS-misconfigured domain can leak sensitive data cross-origin",
                "steps": [
                    f"XSS found at: {xss_found[0].get('url')}",
                    f"CORS misconfiguration on: {cors_found[0].get('url')}",
                    "Chain: Use XSS to make cross-origin requests and exfiltrate data"
                ],
                "severity": "critical"
            }
            analysis["potential_chains"].append(chain)

        ssrf_found = [v for v in vulns if "ssrf" in v.get("type", "").lower()]
        if ssrf_found:
            chain = {
                "name": "SSRF → Cloud Metadata Access → Credential Theft",
                "description": "SSRF can access cloud provider metadata endpoints to steal IAM credentials",
                "steps": [
                    f"SSRF found at: {ssrf_found[0].get('url')}",
                    "Test: http://169.254.169.254/latest/meta-data/",
                    "Impact: Full cloud account compromise"
                ],
                "severity": "critical"
            }
            analysis["potential_chains"].append(chain)

        return analysis

    def generate_highlights(self, phases: dict) -> list:
        highlights = []
        for phase_name, phase_data in phases.items():
            analysis = phase_data.get("analysis", {})
            recs = analysis.get("recommendations", [])
            for rec in recs:
                if any(word in rec.lower() for word in ["critical", "high", "urgent", "takeover", "secrets", "sensitive"]):
                    highlights.append(f"[{phase_name}] {rec}")

            vulns = analysis.get("confirmed_vulns", {})
            for sev in ["critical", "high"]:
                for v in vulns.get(sev, []):
                    highlights.append(
                        f"[{sev.upper()}] {v.get('type', 'Unknown')} at {v.get('url', 'N/A')}"
                    )

        return highlights[:50]

    def save_analysis(self, phase: str, analysis: dict):
        self.findings["phases"][phase] = analysis
        filepath = self.analysis_dir / f"{phase}-analysis.json"
        with open(filepath, "w") as f:
            json.dump(analysis, f, indent=2)

        md_path = self.analysis_dir / f"{phase}-summary.txt"
        with open(md_path, "w") as f:
            f.write(f"=== {phase.upper()} ANALYSIS ===\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Timestamp: {datetime.utcnow().isoformat()}\n\n")

            recs = analysis.get("recommendations", [])
            if recs:
                f.write("Recommendations:\n")
                for r in recs:
                    f.write(f"  → {r}\n")
                f.write("\n")

            int_hosts = analysis.get("interesting_hosts", {})
            if int_hosts:
                f.write("Interesting Subdomains:\n")
                for cat, subs in int_hosts.items():
                    f.write(f"  [{cat.upper()}] {len(subs)} found\n")
                    for s in subs[:5]:
                        f.write(f"    - {s}\n")
                f.write("\n")

            chains = analysis.get("potential_chains", [])
            if chains:
                f.write("Potential Attack Chains:\n")
                for c in chains:
                    f.write(f"  [CHAIN] {c['name']} ({c['severity']})\n")
                    for step in c.get("steps", []):
                        f.write(f"    - {step}\n")
                f.write("\n")

    def save_highlights(self, highlights: list):
        filepath = self.analysis_dir / "highlights.txt"
        with open(filepath, "w") as f:
            f.write(f"=== HIGHLIGHTS for {self.target} ===\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}\n\n")
            for h in highlights:
                f.write(f"⭐ {h}\n")
        return str(filepath)

    def finalize(self):
        self.findings["highlights"] = self.generate_highlights(self.findings["phases"])
        self.save_highlights(self.findings["highlights"])

        filepath = self.analysis_dir / "full-analysis.json"
        with open(filepath, "w") as f:
            json.dump(self.findings, f, indent=2)

        return str(filepath)
