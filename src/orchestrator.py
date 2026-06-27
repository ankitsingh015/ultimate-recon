#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.checker import ToolChecker, DependencyChecker
from src.database import ReconDatabase
from src.analyzer import ReconAnalyzer
from src.tool_registry import ToolRegistry
from src.modules.phase1_recon import Phase1
from src.modules.phase2_live_urls import Phase2
from src.modules.phase3_deep_recon import Phase3
from src.modules.phase4_vulns import Phase4
from src.modules.phase5_report import Phase5


class Orchestrator:
    def __init__(self):
        self.args = self._parse_args()

        if self.args.list_tools:
            self._list_tools()
            sys.exit(0)

        if self.args.setup_keys:
            self._setup_keys_wizard()
            sys.exit(0)

        if not self.args.target and not self.args.tool:
            print("\n  [!] Target domain required\n")
            print("  Usage: ultimate-recon example.com\n")
            print("  Use --list-tools to see single tools\n")
            sys.exit(1)

        self.target = self.args.target

        if self.args.output:
            self.output_dir = Path(self.args.output)
        else:
            self.output_dir = Path("output") / self.target.replace("/", "_").replace(":", "_")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.all_results_dir = self.output_dir / "all_results"
        self.all_results_dir.mkdir(exist_ok=True)

        self.config = self._load_config()
        self.api_keys = self._load_env_and_api_keys()
        self.db = ReconDatabase(str(self.output_dir))
        self.analyzer = ReconAnalyzer(str(self.output_dir), self.target)
        self.start_time = time.time()
        self.shutdown_flag = False

        self._setup_signal_handlers()

    def _parse_args(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="Ultimate Recon — Complete Bug Bounty Reconnaissance",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  Full pipeline:
    ultimate-recon example.com
    ultimate-recon example.com --stealth
    ultimate-recon example.com --phase 1,2

  Single tool (runs one tool, saves output + runs AI analysis):
    ultimate-recon example.com --tool subfinder
    ultimate-recon example.com --tool httpx --output ~/my-recon/example
    ultimate-recon example.com --tool nuclei --output ./results

  List available tools:
    ultimate-recon --list-tools
    ultimate-recon --list-tools --category subdomain
            """
        )
        parser.add_argument("target", nargs="?", default=None, help="Target domain to recon")
        parser.add_argument("--tool", help="Run a single tool by name (use --list-tools to see all)")
        parser.add_argument("--output", "-o", help="Custom output directory for single tool results")
        parser.add_argument("--list-tools", action="store_true", help="List all available single tools")
        parser.add_argument("--category", help="Filter --list-tools by category")
        parser.add_argument("--setup-keys", action="store_true", help="Interactive API key setup wizard")
        parser.add_argument("--phase", help="Specific phase(s) to run (comma-separated: 1,2,3,4,5)")
        parser.add_argument("--stealth", action="store_true", help="Skip aggressive scans")
        parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
        parser.add_argument("--only-missing", action="store_true", help="Only run tools with newly configured API keys")
        parser.add_argument("--verbose", action="store_true", default=True)
        parser.add_argument("--threads", type=int, default=50, help="Thread count for parallel tasks")
        return parser.parse_args()

    def _load_config(self) -> dict:
        config_path = Path("config/settings.yaml")
        if config_path.exists():
            import yaml
            with open(config_path) as f:
                return yaml.safe_load(f) or {}
        return {}

    def _load_env_and_api_keys(self) -> dict:
        keys = {}

        # Priority 1: .env file (most secure, gitignored)
        try:
            from dotenv import load_dotenv, dotenv_values
            env_path = Path(".env")
            if env_path.exists():
                env_values = dotenv_values(str(env_path))
                for k, v in env_values.items():
                    if v:  # Only set non-empty values
                        key_name = k.lower().replace("_api_key", "").replace("_token", "").replace("_key", "")
                        keys[key_name] = v
        except ImportError:
            # Fallback: manually parse .env
            env_path = Path(".env")
            if env_path.exists():
                with open(env_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip("'\"")
                            if v:
                                key_name = k.lower().replace("_api_key", "").replace("_token", "").replace("_key", "")
                                keys[key_name] = v

        # Priority 2: config/api-keys.yaml (gitignored)
        try:
            api_path = Path("config/api-keys.yaml")
            if api_path.exists():
                import yaml
                with open(api_path) as f:
                    yaml_keys = yaml.safe_load(f) or {}
                    for k, v in yaml_keys.items():
                        if v and k not in keys:
                            keys[k] = v
        except Exception:
            pass

        # Priority 3: Environment variables (OS-level)
        env_var_map = {
            "SHODAN_API_KEY": "shodan",
            "SHODAN": "shodan",
            "GITHUB_TOKEN": "github",
            "CHAOS_API_KEY": "chaos",
            "VIRUSTOTAL_API_KEY": "virustotal",
            "SECURITYTRAILS_API_KEY": "securitytrails",
            "URLSCAN_API_KEY": "urlscan",
            "HACKERTARGET_API_KEY": "hackertarget",
            "ALIENVAULT_API_KEY": "alienvault",
        }
        for env_var, key_name in env_var_map.items():
            val = os.environ.get(env_var)
            if val and key_name not in keys:
                keys[key_name] = val

        return keys

    def _scrub_sensitive(self, text: str) -> str:
        if not text or not self.api_keys:
            return text
        result = text
        for _, key_value in self.api_keys.items():
            if key_value and len(key_value) > 4:
                result = result.replace(key_value, "***REDACTED***")
        return result

    def _setup_signal_handlers(self):
        def handler(signum, frame):
            if not self.shutdown_flag:
                print("\n\n[!] Received shutdown signal. Saving checkpoint and exiting...")
                self.shutdown_flag = True
                self.db.save_checkpoint("shutdown", "interrupted", {
                    "phase": "unknown",
                    "elapsed": time.time() - self.start_time
                })
                sys.exit(0)
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def print_banner(self):
        banner = """
╔════════════════════════════════════════════════════╗
║              ULTIMATE RECON v1.0                   ║
║     Complete Bug Bounty Reconnaissance Toolkit     ║
╚════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"  Target: {self.target}")
        print(f"  Output: {self.output_dir}")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

    def run_command(self, cmd: str, timeout: int = 600, env: dict = None) -> subprocess.CompletedProcess:
        import shlex
        if self.args.verbose and not cmd.startswith("sleep"):
            safe_cmd = self._scrub_sensitive(cmd[:150])
            print(f"    $ {safe_cmd}...")
        try:
            result = subprocess.run(
                shlex.split(cmd) if isinstance(cmd, str) else cmd,
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, **(env or {})}
            )
            return result
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr="TIMEOUT")
        except Exception as e:
            return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr=str(e))

    def run_parallel(self, tasks: Dict[str, Dict], max_workers: int = None) -> Dict[str, Any]:
        if max_workers is None:
            max_workers = self.args.threads

        results = {}
        pending = {}
        completed = set()
        failed = set()

        for name, task in tasks.items():
            deps = task.get("depends", [])
            if not deps or all(d in completed for d in deps):
                pending[name] = task
            else:
                failed_deps = [d for d in deps if d not in completed]
                if failed_deps:
                    failed.add(name)

        with ThreadPoolExecutor(max_workers=min(max_workers, len(pending))) as executor:
            futures = {}
            for name, task in pending.items():
                future = executor.submit(self._execute_task, name, task)
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results[name] = result
                    if result.get("success"):
                        completed.add(name)
                    else:
                        failed.add(name)
                except Exception as e:
                    results[name] = {"success": False, "error": str(e)}
                    failed.add(name)

        return results

    def _execute_task(self, name: str, task: Dict) -> Dict:
        if self.shutdown_flag:
            return {"success": False, "error": "shutdown"}

        func = task.get("func")
        cmd = task.get("cmd")
        timeout = task.get("timeout", 600)

        if func:
            try:
                result = func()
                return {"success": True, "result": result}
            except Exception as e:
                return {"success": False, "error": str(e)}

        if cmd:
            result = self.run_command(cmd, timeout)
            output = result.stdout + result.stderr
            if result.returncode == -1:
                return {"success": False, "error": "timeout"}
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "output_size": len(output)
            }

        return {"success": False, "error": "no task defined"}

    def update_progress(self, phase: int, total: int, current: int, message: str = ""):
        pct = (current / total) * 100 if total > 0 else 0
        bar_len = 40
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(f"\r  [{bar}] {pct:.0f}% ({current}/{total}) {message}")
        sys.stdout.flush()
        if current == total:
            print()

    async def phase0_check(self) -> bool:
        print("\n[PHASE 0] Environment Check")
        print("-" * 50)

        dep_checker = DependencyChecker()
        if not dep_checker.check_python_version():
            print("  [!] Python 3.8+ required")
            return False

        free_gb, ok = dep_checker.check_disk_space(str(self.output_dir))
        if not ok:
            print(f"  [!] Low disk space: {free_gb:.1f}GB free")
        else:
            print(f"  [✓] Disk space: {free_gb:.1f}GB free")

        has_net = dep_checker.check_network()
        if has_net:
            print("  [✓] Network: connected")
        else:
            print("  [!] Network: no connection — some tools may fail")

        checker = ToolChecker("config")
        results = checker.check_all()
        print(checker.summary())

        if results["missing"]:
            missing_str = ", ".join(results["missing"][:10])
            print(f"  [!] Missing tools: {missing_str}{'...' if len(results['missing']) > 10 else ''}")

        api_results = checker.check_api_keys()
        configured = api_results.get("configured_count", 0)
        total_api = api_results.get("total", 0)
        print(f"  [{'✓' if configured > 0 else ' '}] API keys: {configured}/{total_api} configured")

        self.db.save_checkpoint("phase0", "completed", {
            "tools": results,
            "api_keys": api_results
        })

        print()
        return True

    def run_phase(self, phase_num: int, phase_module) -> dict:
        phase_name = f"phase{phase_num}"
        print(f"\n[PHASE {phase_num}] {phase_module.NAME}")
        print("-" * 60)

        self.db.save_checkpoint(phase_name, "running")

        phase_data = phase_module.run(self)

        self.db.save_checkpoint(phase_name, "completed", {
            "summary": phase_data.get("summary", {}),
            "counts": {k: len(v) if isinstance(v, (list, dict)) else v for k, v in phase_data.items() if isinstance(v, (list, dict))}
        })

        analysis = self.analyzer.analyze_fn(phase_data)
        self.analyzer.save_analysis(phase_name, analysis)
        self.analyzer.findings["phases"][phase_name] = analysis

        elapsed = time.time() - self.start_time
        recs = analysis.get("recommendations", [])
        if recs:
            print(f"\n  🧠 Analysis — Top Recommendations:")
            for r in recs[:5]:
                print(f"    → {r}")

        print(f"\n  ⏱️  Elapsed: {elapsed:.0f}s")
        return phase_data

    def _list_tools(self):
        print("\n╔════════════════════════════════════════════════════╗")
        print("║          AVAILABLE SINGLE TOOLS                   ║")
        print("╚════════════════════════════════════════════════════╝")
        print()

        if self.args.category:
            tools = ToolRegistry.list_by_category(self.args.category)
            print(f"  Category: {self.args.category} ({len(tools)} tools)")
            print()
        else:
            categories = ToolRegistry.categories()
            for cat, tools in sorted(categories.items()):
                print(f"  [{cat.upper()}] ({len(tools)} tools)")
                for t in sorted(tools, key=lambda x: x["name"]):
                    api = f" [needs: {t['needs_api']}]" if t.get("needs_api") else ""
                    phase = f" [phase {t['phase']}]" if t.get("phase") else ""
                    print(f"    {t['name']:<20} {t['description']}{api}{phase}")
                print()
            return

        tools = ToolRegistry.list_by_category(self.args.category)
        for t in sorted(tools, key=lambda x: x["name"]):
            api = f" [needs: {t['needs_api']}]" if t.get("needs_api") else ""
            phase = f" [phase {t['phase']}]" if t.get("phase") else ""
            print(f"  {t['name']:<25} {t['description']}{api}{phase}")

        print()
        print("  Usage: ultimate-recon example.com --tool <name>")
        print("         ultimate-recon example.com --tool httpx --output ./my-results")
        print()

    def run_single_tool(self):
        tool_name = self.args.tool
        tool = ToolRegistry.get(tool_name)
        if not tool:
            print(f"\n  [!] Unknown tool: '{tool_name}'")
            print(f"  Use --list-tools to see all available tools\n")
            sys.exit(1)

        print(f"\n[TOOL] {tool_name}")
        print("-" * 60)
        print(f"  Category:    {tool['category']}")
        print(f"  Description: {tool['description']}")
        print(f"  Output:      {self.output_dir}")
        print()

        if tool.get("needs_api"):
            key = self.api_keys.get(tool["needs_api"], "")
            if not key:
                print(f"  [!] This tool needs an API key for '{tool['needs_api']}'")
                print(f"  Add it to config/api-keys.yaml or use a different tool\n")
                sys.exit(1)

        output_filename = f"{tool_name}{tool['output_ext']}"
        output_path = self.all_results_dir / output_filename

        cmd = ToolRegistry.build_cmd(tool_name, self.target, output_path, self.api_keys)
        if not cmd:
            print(f"  [!] Failed to build command for '{tool_name}'\n")
            sys.exit(1)

        safe_cmd = self._scrub_sensitive(cmd[:120])
        print(f"  Running: {safe_cmd}...")
        print()

        result = self.run_command(cmd, timeout=tool.get("timeout", 300))

        if result.stdout:
            with open(output_path, "w") as f:
                f.write(result.stdout)
            if result.stderr:
                with open(output_path, "a") as f:
                    f.write("\n# STDERR:\n" + result.stderr)

            lines = [l.strip() for l in result.stdout.split("\n") if l.strip()]
            print(f"  [✓] Output: {len(lines)} lines -> {output_path}")
        else:
            with open(output_path, "w") as f:
                f.write(result.stderr if result.stderr else "No output")
            print(f"  [!] Tool produced no stdout. Stderr logged.")

        findings = {
            "tool": tool_name,
            "target": self.target,
            "cmd": cmd,
            "output_file": str(output_path),
            "lines": len(result.stdout.split("\n")) if result.stdout else 0,
            "success": result.returncode == 0,
            "raw_output": result.stdout,
            "analysis": {}
        }
        self.db.save_raw(f"single_tool_{tool_name}", result.stdout, output_filename)

        print(f"\n  [*] Running AI analysis on single tool output...")
        analysis = self._analyze_single_tool(tool_name, tool, result.stdout, output_path)
        findings["analysis"] = analysis

        analysis_path = self.output_dir / "analysis" / f"single-tool-{tool_name}-analysis.txt"
        analysis_path.parent.mkdir(parents=True, exist_ok=True)
        with open(analysis_path, "w") as f:
            f.write(f"=== Single Tool Analysis: {tool_name} ===\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Timestamp: {datetime.utcnow().isoformat()}\n\n")
            if analysis.get("summary"):
                f.write("Summary:\n")
                for k, v in analysis["summary"].items():
                    f.write(f"  {k}: {v}\n")
                f.write("\n")
            if analysis.get("findings"):
                f.write("Findings:\n")
                for finding in analysis["findings"]:
                    f.write(f"  [{finding.get('severity', 'info').upper()}] {finding.get('message', '')}\n")
                f.write("\n")
            if analysis.get("recommendations"):
                f.write("Recommendations:\n")
                for r in analysis["recommendations"]:
                    f.write(f"  → {r}\n")
                f.write("\n")

        print(f"  [✓] Analysis: {analysis_path}")
        print()
        return findings

    def _setup_keys_wizard(self):
        print("\n╔══════════════════════════════════════════════╗")
        print("║       API Key Setup Wizard                  ║")
        print("╚══════════════════════════════════════════════╝")
        print()
        print("  API keys are OPTIONAL. The tool works without them,")
        print("  but some data sources will be unavailable.")
        print()

        env_path = Path(".env")
        if not env_path.exists():
            example_path = Path(".env.example")
            if example_path.exists():
                import shutil
                shutil.copy(str(example_path), str(env_path))
                print("  [✓] Created .env from .env.example")
            else:
                env_path.write_text("# Ultimate Recon API Keys\n")
                print("  [✓] Created empty .env")

        print("  Edit .env to add your keys:")
        print(f"    nano {env_path.resolve()}")
        print(f"    vim {env_path.resolve()}")
        print()
        print("  After editing, verify with:")
        print(f"    python3 {sys.argv[0]} <target>")
        print()

    def _analyze_single_tool(self, tool_name: str, tool: dict, output: str, output_path: Path) -> dict:
        analysis = {
            "tool": tool_name,
            "category": tool["category"],
            "summary": {},
            "findings": [],
            "recommendations": []
        }

        lines = [l.strip() for l in output.split("\n") if l.strip()]
        analysis["summary"]["total_lines"] = len(lines)

        if not lines:
            analysis["summary"]["status"] = "no results"
            return analysis

        category = tool["category"]

        if category == "subdomain":
            interesting = [l for l in lines if any(kw in l.lower() for kw in
                ["admin", "dev", "staging", "api", "test", "internal", "backup", "db", "mail"])]
            if interesting:
                analysis["findings"].append({
                    "severity": "info",
                    "message": f"{len(interesting)} interesting subdomains found (admin/dev/api/internal patterns)"
                })
                analysis["recommendations"].append("Review interesting subdomains for deeper testing")
            analysis["summary"]["total_found"] = len(lines)

        elif category == "url":
            sensitive_exts = [".sql", ".db", ".bak", ".env", ".git", ".json", ".pdf", ".xls", ".doc"]
            sensitive = [l for l in lines if any(l.lower().endswith(e) for e in sensitive_exts)]
            if sensitive:
                analysis["findings"].append({
                    "severity": "medium",
                    "message": f"{len(sensitive)} potentially sensitive files found"
                })
                analysis["recommendations"].append("Check sensitive files for information disclosure")
            with_params = [l for l in lines if "=" in l]
            analysis["summary"]["urls_with_params"] = len(with_params)
            analysis["summary"]["total_urls"] = len(lines)

        elif category == "param":
            analysis["summary"]["total_params"] = len(lines)
            if len(lines) > 10:
                analysis["findings"].append({
                    "severity": "info",
                    "message": f"{len(lines)} parameters found — ready for vulnerability testing"
                })

        elif category == "vuln":
            vuln_lines = [l for l in lines if any(kw in l.lower() for kw in
                ["critical", "high", "cve-", "vuln", "xss", "sqli", "lfi", "rce", "takeover"])]
            if vuln_lines:
                analysis["findings"].append({
                    "severity": "high",
                    "message": f"{len(vuln_lines)} potential vulnerabilities detected"
                })
                analysis["recommendations"].append("Manually verify each finding before reporting")
            analysis["summary"]["potential_vulns"] = len(vuln_lines)

        elif category == "js":
            secrets_found = [l for l in lines if any(kw in l.lower() for kw in
                ["api_key", "secret", "token", "password", "aws", "bucket", "slack", "firebase", "jwt"])]
            if secrets_found:
                analysis["findings"].append({
                    "severity": "high",
                    "message": f"{len(secrets_found)} potential secrets found in JS"
                })
                analysis["recommendations"].append("Validate secrets immediately — may lead to account compromise")
            analysis["summary"]["total_js"] = len(lines)

        elif category == "port":
            open_ports = len(lines)
            analysis["summary"]["open_ports"] = open_ports
            unusual_ports = [l for l in lines if any(str(p) in l for p in [22, 5432, 3306, 6379, 27017, 9200])]
            if unusual_ports:
                analysis["findings"].append({
                    "severity": "medium",
                    "message": f"Unusual services detected (SSH, DB, Redis, ES...) — review ports"
                })

        elif category == "tech":
            analysis["summary"]["technologies"] = len(lines)
            outdated = [l for l in lines if any(kw in l.lower() for kw in ["old", "outdated", "eol", "deprecated"])]
            if outdated:
                analysis["findings"].append({
                    "severity": "medium",
                    "message": "Outdated technologies detected — check for known CVEs"
                })

        elif category == "dir":
            analysis["summary"]["directories_found"] = len(lines)
            sensitive_dirs = [l for l in lines if any(kw in l.lower() for kw in
                ["admin", "backup", "config", "api", "wp-admin", "dashboard", "phpmyadmin", "server-status"])]
            if sensitive_dirs:
                analysis["findings"].append({
                    "severity": "high",
                    "message": f"Sensitive directories found: {', '.join(sensitive_dirs[:5])}"
                })

        else:
            analysis["summary"]["results"] = len(lines)
            if len(lines) > 0:
                analysis["findings"].append({
                    "severity": "info",
                    "message": f"{len(lines)} results obtained from {tool_name}"
                })

        if analysis["findings"]:
            analysis["recommendations"].append("Cross-reference findings with other tools for validation")

        return analysis

    async def run(self):
        if self.args.tool:
            if not self.target:
                print("\n  [!] Target domain required when using --tool\n")
                print("  Usage: ultimate-recon example.com --tool <name>\n")
                sys.exit(1)
            self.print_banner()
            self.run_single_tool()
            self.db.close()
            return

        self.print_banner()

        if not await self.phase0_check():
            sys.exit(1)

        self.db.save_checkpoint("start", "running", {"target": self.target})

        phases_to_run = [1, 2, 3, 4, 5]
        if self.args.phase:
            phases_to_run = [int(p.strip()) for p in self.args.phase.split(",")]
        elif self.args.resume:
            cp = self.db.get_checkpoint()
            if cp and cp["phase"].startswith("phase"):
                last_phase = int(cp["phase"].replace("phase", ""))
                phases_to_run = [p for p in range(last_phase, 6)]
                print(f"  [*] Resuming from phase {last_phase}")

        if self.args.stealth:
            print("  [*] Stealth mode — skipping aggressive scans\n")

        phase_modules = {
            1: Phase1(),
            2: Phase2(),
            3: Phase3(),
            4: Phase4(),
            5: Phase5()
        }

        all_results = {}
        for pnum in phases_to_run:
            if pnum in phase_modules:
                if self.shutdown_flag:
                    break
                result = self.run_phase(pnum, phase_modules[pnum])
                all_results[f"phase{pnum}"] = result

        self.analyzer.finalize()

        elapsed = time.time() - self.start_time
        self.db.save_checkpoint("complete", "completed", {
            "elapsed": elapsed,
            "phases_completed": phases_to_run
        })

        stats = self.db.get_stats(1)  # target_id=1 for single target
        print("\n" + "=" * 60)
        print("  FINAL SUMMARY")
        print("=" * 60)
        print(f"  Target:      {self.target}")
        print(f"  Time:        {elapsed:.0f}s ({elapsed/60:.1f}m)")
        print(f"  Subdomains:  {stats.get('subdomains', '?')}")
        print(f"  URLs:        {stats.get('urls', '?')}")
        print(f"  Findings:    {stats.get('findings', '?')}")
        print(f"    Critical:  {stats.get('critical', 0)}")
        print(f"    High:      {stats.get('high', 0)}")
        print(f"    Medium:    {stats.get('medium', 0)}")
        print(f"    Low:       {stats.get('low', 0)}")
        print(f"  Report:      {self.output_dir}/report.html")
        print()

        highlights_file = self.analyzer.analysis_dir / "highlights.txt"
        if highlights_file.exists():
            print(f"  Highlights:  {highlights_file}")
        print()

        self.db.close()


async def main():
    orch = Orchestrator()
    await orch.run()


if __name__ == "__main__":
    asyncio.run(main())
