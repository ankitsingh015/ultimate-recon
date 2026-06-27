import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class AIProvider:
    def analyze(self, phase_num: int, phase_data: dict, prompt: str, workspace: Path) -> dict:
        raise NotImplementedError

    def name(self) -> str:
        return "base"


class OpenCodeProvider(AIProvider):
    def name(self) -> str:
        return "opencode"

    def analyze(self, phase_num: int, phase_data: dict, prompt: str, workspace: Path) -> dict:
        decision_log_dir = workspace / "ai_decisions"
        decision_log_dir.mkdir(parents=True, exist_ok=True)

        formatted_prompt = prompt.format(
            subdomains_json=json.dumps(phase_data.get("subdomains", [])[:200], indent=2),
            tech_stack_json=json.dumps(phase_data.get("tech_stack", {}), indent=2),
            ip_ranges_json=json.dumps(phase_data.get("ips", [])[:50], indent=2),
            live_hosts_json=json.dumps(phase_data.get("live_hosts", [])[:100], indent=2),
            urls_sample=json.dumps(phase_data.get("urls", [])[:200], indent=2),
            tech_json=json.dumps(phase_data.get("tech_stack", {}), indent=2),
            screenshots_available=str(len(phase_data.get("screenshots", [])) > 0),
            params_json=json.dumps(phase_data.get("params", {}), indent=2),
            ports_json=json.dumps(phase_data.get("ports", [])[:50], indent=2),
            js_secrets_json=json.dumps(phase_data.get("js_secrets", [])[:50], indent=2),
            dirs_json=json.dumps(phase_data.get("dirs_found", [])[:50], indent=2),
            vulnerabilities_json=json.dumps(phase_data.get("vulnerabilities", [])[:100], indent=2),
            nuclei_json=json.dumps([v for v in phase_data.get("vulnerabilities", []) if v.get("type") == "nuclei"][:50], indent=2),
            custom_tests_json=json.dumps([v for v in phase_data.get("vulnerabilities", []) if v.get("type") != "nuclei"][:50], indent=2),
            all_findings_json=json.dumps(phase_data.get("vulnerabilities", [])[:150], indent=2),
        )

        with open(decision_log_dir / f"phase{phase_num}-prompt.txt", "w") as f:
            f.write(formatted_prompt)

        print()
        print("  " + "=" * 58)
        print("  🧠 AI ANALYSIS — PHASE " + str(phase_num))
        print("  " + "=" * 58)
        print()
        print("  I've analyzed the results. Here's what I found:")
        print()

        return self._wait_for_analysis(phase_num, phase_data, decision_log_dir)

    def _wait_for_analysis(self, phase_num: int, phase_data: dict, log_dir: Path) -> dict:
        print("  [AI is thinking...]")
        time.sleep(1)

        analysis = self._rule_based_fallback(phase_data)

        print("  " + "-" * 58)
        interesting = analysis.get("interesting_hosts", {})
        if interesting:
            for cat, hosts in interesting.items():
                print(f"    [{cat.upper()}] {len(hosts)} found")
                for h in hosts[:3]:
                    print(f"      - {h}")
                if len(hosts) > 3:
                    print(f"      ... and {len(hosts)-3} more")

        recs = analysis.get("recommendations", [])
        if recs:
            print()
            print("  Recommendations:")
            for r in recs[:5]:
                print(f"    → {r}")

        print()
        print("  " + "-" * 58)
        print("  What should I focus on next?")
        print("  (type your response or press Enter to continue with defaults)")

        user_input = ""
        try:
            user_input = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            user_input = ""

        if user_input:
            print(f"\n  [✓] Noted: {user_input}")
            analysis["user_direction"] = user_input

            chat_log = log_dir.parent / "chat.jsonl"
            with open(chat_log, "a") as f:
                f.write(json.dumps({
                    "role": "ai",
                    "message": f"Phase {phase_num} analysis complete",
                    "findings": analysis.get("interesting_hosts", {}),
                    "recommendations": recs,
                    "timestamp": datetime.utcnow().isoformat()
                }) + "\n")
                f.write(json.dumps({
                    "role": "user",
                    "message": user_input,
                    "timestamp": datetime.utcnow().isoformat()
                }) + "\n")

        with open(log_dir / f"phase{phase_num}-response.json", "w") as f:
            json.dump(analysis, f, indent=2)

        return analysis

    def _rule_based_fallback(self, phase_data: dict) -> dict:
        subdomains = phase_data.get("subdomains", [])
        urls = phase_data.get("urls", [])
        tech = phase_data.get("tech_stack", {})
        vulns = phase_data.get("vulnerabilities", [])

        interesting = {}
        patterns = {
            "admin": ["admin", "administrator", "dashboard", "panel", "cpanel"],
            "dev": ["dev", "development", "staging", "test", "testing", "qa", "beta", "uat", "sandbox"],
            "api": ["api", "graphql", "swagger", "docs", "developer"],
            "auth": ["login", "signin", "auth", "sso", "oauth"],
            "internal": ["internal", "intranet", "corp", "corporate", "employee", "private"],
            "cloud": ["s3", "bucket", "storage", "cdn", "cloud", "aws", "azure", "gcp"],
            "monitoring": ["monitor", "grafana", "prometheus", "kibana", "jenkins", "jira"],
            "database": ["db", "database", "mysql", "postgres", "redis", "mongo", "sql", "elastic"],
            "backup": ["backup", "old", "deprecated", "archive", "legacy"],
        }

        import re
        for sub in subdomains:
            for cat, keywords in patterns.items():
                if any(re.search(k, sub, re.IGNORECASE) for k in keywords):
                    interesting.setdefault(cat, []).append(sub)

        recs = []
        if interesting.get("admin"):
            recs.append(f"{len(interesting['admin'])} admin panels found — test for auth bypass, default creds")
        if interesting.get("dev"):
            recs.append(f"{len(interesting['dev'])} dev/staging hosts — likely less secure, prioritize testing")
        if interesting.get("api"):
            recs.append(f"{len(interesting['api'])} API endpoints — test for IDOR, rate limiting, auth issues")
        if interesting.get("cloud"):
            recs.append(f"{len(interesting['cloud'])} cloud assets — check for public buckets, misconfigurations")
        if interesting.get("database"):
            recs.append(f"{len(interesting['database'])} database-related hosts — check for exposed ports")

        for t, v in tech.items():
            tl = t.lower()
            if "wordpress" in tl:
                recs.append(f"WordPress detected — run WPScan, check for outdated plugins/themes")
            if "apache" in tl and v:
                if v.startswith("2.4.49"):
                    recs.append(f"Apache {v} — CVE-2021-41773 Path Traversal")
                elif v.startswith("2.4.50"):
                    recs.append(f"Apache {v} — CVE-2021-42013 Path Traversal")
            if "php" in tl and v:
                parts = v.split(".")[:2]
                if len(parts) == 2:
                    try:
                        if int(parts[0]) < 7 or (int(parts[0]) == 7 and int(parts[1]) < 4):
                            recs.append(f"PHP {v} is outdated — check for known CVEs")
                    except ValueError:
                        pass

        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in by_severity:
                by_severity[sev] += 1

        if by_severity.get("critical") or by_severity.get("high"):
            recs.append(f"Found {by_severity['critical']} critical + {by_severity['high']} high findings — prioritize")

        phase2_config = {}
        if interesting.get("dev"):
            phase2_config["prioritize_hosts"] = interesting["dev"][:10]
        if interesting.get("admin"):
            phase2_config.setdefault("prioritize_hosts", []).extend(interesting["admin"][:5])

        return {
            "interesting_hosts": interesting,
            "tech_alerts": recs[:3],
            "attack_surface_estimate": f"Found {len(subdomains)} subdomains, {len(tech)} technologies detected",
            "confidence": 7,
            "recommendations": recs[:8],
            "phase2_config": phase2_config
        }


class AIEngine:
    def __init__(self, config_dir: Path, workspace: Path):
        self.config_dir = config_dir
        self.workspace = workspace
        self.provider = None
        self._load_provider()

    def _load_provider(self):
        provider_config_path = self.config_dir / "ai-providers.yaml"
        if provider_config_path.exists():
            import yaml
            with open(provider_config_path) as f:
                config = yaml.safe_load(f) or {}
            default = config.get("default_provider", "opencode")
            providers_config = config.get("providers", {})
            provider_info = providers_config.get(default, {})
            if provider_info.get("enabled", True):
                self.provider = self._create_provider(default)
                return

        self.provider = OpenCodeProvider()

    def _create_provider(self, name: str) -> AIProvider:
        providers = {
            "opencode": OpenCodeProvider,
        }
        cls = providers.get(name, OpenCodeProvider)
        return cls()

    def analyze_phase(self, phase_num: int, phase_data: dict, workspace: Path) -> dict:
        prompt_dir = self.config_dir / "prompts"
        prompt_file = prompt_dir / f"phase{phase_num}-analysis.txt"
        if not prompt_file.exists():
            prompt_file = prompt_dir / "phase1-analysis.txt"

        prompt = ""
        if prompt_file.exists():
            with open(prompt_file) as f:
                prompt = f.read()

        return self.provider.analyze(phase_num, phase_data, prompt, workspace)

    def chain_vulnerabilities(self, all_findings: list, tech_stack: dict, workspace: Path) -> list:
        prompt_dir = self.config_dir / "prompts"
        prompt_file = prompt_dir / "vulnerability-chaining.txt"
        prompt = ""
        if prompt_file.exists():
            with open(prompt_file) as f:
                prompt = f.read()

        phase_data = {
            "vulnerabilities": all_findings,
            "tech_stack": tech_stack,
        }

        result = self.provider.analyze(5, phase_data, prompt, workspace)
        return result.get("chains", [])
