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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.checker import ToolChecker, DependencyChecker
from src.database import ReconDatabase
from src.analyzer import ReconAnalyzer
from src.ai_engine import AIEngine
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

        if self.args.list_workspaces:
            self._list_workspaces()
            sys.exit(0)

        if self.args.setup_keys:
            self._setup_keys_wizard()
            sys.exit(0)

        if self.args.web:
            self._launch_web_ui()
            return

        if not self.args.target and not self.args.tool:
            print("\n  [!] Target domain required\n")
            print("  Usage: ultimate-recon example.com\n")
            print("  Use --list-tools to see single tools\n")
            sys.exit(1)

        self.target = self.args.target

        workspaces_dir = Path("workspaces")
        workspaces_dir.mkdir(exist_ok=True)

        if self.args.output:
            self.output_dir = Path(self.args.output)
        else:
            self.output_dir = workspaces_dir / self.target.replace("/", "_").replace(":", "_")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.all_results_dir = self.output_dir / "all_results"
        self.all_results_dir.mkdir(exist_ok=True)

        self.workspace_config = self.output_dir / "config.yaml"
        self.workspace_meta = self.output_dir / "target.yaml"

        self.config = self._load_config()
        self.api_keys = self._load_env_and_api_keys()
        self.db = ReconDatabase(str(self.output_dir))
        self.ai_engine = AIEngine(Path("config"), self.output_dir)
        self.analyzer = ReconAnalyzer(str(self.output_dir), self.target, ai_engine=self.ai_engine)
        self.start_time = time.time()
        self.shutdown_flag = False

        self._init_workspace()
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

  Single tool:
    ultimate-recon example.com --tool subfinder
    ultimate-recon example.com --tool httpx --output /results

  Workspaces:
    ultimate-recon --list-workspaces
    ultimate-recon example.com --resume

  AI integration:
    ultimate-recon example.com --ai opencode
    ultimate-recon --web
            """
        )
        parser.add_argument("target", nargs="?", default=None, help="Target domain to recon")
        parser.add_argument("--tool", help="Run a single tool by name")
        parser.add_argument("--output", "-o", help="Custom output directory")
        parser.add_argument("--list-tools", action="store_true", help="List all available single tools")
        parser.add_argument("--list-workspaces", action="store_true", help="List all workspaces")
        parser.add_argument("--category", help="Filter --list-tools by category")
        parser.add_argument("--setup-keys", action="store_true", help="API key setup wizard")
        parser.add_argument("--web", action="store_true", help="Launch web UI")
        parser.add_argument("--ai", default="opencode", help="AI provider (default: opencode)")
        parser.add_argument("--phase", help="Specific phase(s) to run (comma-separated: 1,2,3,4,5)")
        parser.add_argument("--stealth", action="store_true", help="Skip aggressive scans")
        parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
        parser.add_argument("--only-missing", action="store_true", help="Only run tools with newly configured API keys")
        parser.add_argument("--verbose", action="store_true", default=True)
        parser.add_argument("--threads", type=int, default=50, help="Thread count for parallel tasks")
        return parser.parse_args()

    def _init_workspace(self):
        if not self.workspace_meta.exists():
            meta = {
                "target": self.target,
                "created": datetime.now(timezone.utc).isoformat(),
                "status": "initialized",
                "phases_completed": [],
                "ai_provider": self.args.ai,
            }
            with open(self.workspace_meta, "w") as f:
                json.dump(meta, f, indent=2)

        self.db.log_session_event(str(self.output_dir), {
            "event": "session_start",
            "target": self.target,
            "ai_provider": self.args.ai,
        })

    def _load_config(self) -> dict:
        config_path = Path("config/settings.yaml")
        if config_path.exists():
            import yaml
            with open(config_path) as f:
                return yaml.safe_load(f) or {}
        return {}

    def _load_env_and_api_keys(self) -> dict:
        keys = {}
        try:
            from dotenv import load_dotenv, dotenv_values
            env_path = Path(".env")
            if env_path.exists():
                env_values = dotenv_values(str(env_path))
                for k, v in env_values.items():
                    if v:
                        key_name = k.lower().replace("_api_key", "").replace("_token", "").replace("_key", "")
                        keys[key_name] = v
        except ImportError:
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

        env_var_map = {
            "SHODAN_API_KEY": "shodan", "SHODAN": "shodan",
            "GITHUB_TOKEN": "github", "CHAOS_API_KEY": "chaos",
            "VIRUSTOTAL_API_KEY": "virustotal", "SECURITYTRAILS_API_KEY": "securitytrails",
            "URLSCAN_API_KEY": "urlscan", "HACKERTARGET_API_KEY": "hackertarget",
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
                print("\n\n[!] Interrupted. Saving checkpoint...")
                self.shutdown_flag = True
                self.db.save_checkpoint("shutdown", "interrupted", {
                    "elapsed": time.time() - self.start_time
                })
                self.db.log_session_event(str(self.output_dir), {"event": "session_interrupted"})
                sys.exit(0)
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _list_workspaces(self):
        ws_dir = Path("workspaces")
        if not ws_dir.exists() or not any(ws_dir.iterdir()):
            print("\n  No workspaces found. Run `ultimate-recon example.com` to create one.\n")
            return
        print("\n  Workspaces:")
        print("  " + "-" * 60)
        for d in sorted(ws_dir.iterdir()):
            if d.is_dir():
                meta_file = d / "target.yaml"
                chat_file = d / "chat.jsonl"
                phases = "?"
                if meta_file.exists():
                    with open(meta_file) as f:
                        meta = json.load(f)
                    phases = ", ".join(str(p) for p in meta.get("phases_completed", [])) or "none"
                msgs = 0
                if chat_file.exists():
                    msgs = sum(1 for _ in open(chat_file) if _.strip())
                print(f"    {d.name:<30} phases: {phases:<15} chats: {msgs}")
        print()

    def _list_tools(self):
        print("\n  Available Single Tools:")
        print("  " + "-" * 60)
        if self.args.category:
            tools = ToolRegistry.list_by_category(self.args.category)
            print(f"  Category: {self.args.category} ({len(tools)} tools)\n")
            for t in sorted(tools, key=lambda x: x["name"]):
                api = f" [needs: {t['needs_api']}]" if t.get("needs_api") else ""
                print(f"    {t['name']:<25} {t['description']}{api}")
        else:
            categories = ToolRegistry.categories()
            for cat, tools in sorted(categories.items()):
                print(f"  [{cat.upper()}] ({len(tools)} tools)")
                for t in sorted(tools, key=lambda x: x["name"])[:5]:
                    api = f" [needs: {t['needs_api']}]" if t.get("needs_api") else ""
                    print(f"    {t['name']:<25} {t['description']}{api}")
                if len(tools) > 5:
                    print(f"    ... and {len(tools)-5} more")
                print()
        print("  Usage: ultimate-recon example.com --tool <name>\n")

    def _setup_keys_wizard(self):
        print("\n  API Key Setup")
        print("  " + "-" * 40)
        print("  API keys are optional. The tool works without them.")
        print()
        env_path = Path(".env")
        if not env_path.exists():
            example = Path(".env.example")
            if example.exists():
                import shutil
                shutil.copy(str(example), str(env_path))
                print("  [✓] Created .env from .env.example")
            else:
                env_path.write_text("# Ultimate Recon API Keys\n")
                print("  [✓] Created empty .env")
        print(f"  Edit: nano {env_path.resolve()}")
        print()

    def _launch_web_ui(self):
        print("\n  [*] Starting Web UI...")
        web_dir = Path(__file__).parent.parent / "web-ui"
        app_file = web_dir / "app.py"
        if not app_file.exists():
            print("  [!] web-ui/app.py not found")
            sys.exit(1)
        os.chdir(str(web_dir.parent))
        os.execvp("python3", ["python3", str(app_file)])

    def run_command(self, cmd: str, timeout: int = 600, env: dict = None) -> subprocess.CompletedProcess:
        if self.args.verbose and not cmd.startswith("sleep"):
            safe_cmd = self._scrub_sensitive(cmd[:200])
            print(f"    $ {safe_cmd}...")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, **(env or {})}
            )
            return result
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr="TIMEOUT")
        except Exception as e:
            return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr=str(e))

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
        print(f"  [{'✓' if has_net else ' '}] Network: {'connected' if has_net else 'no connection'}")
        checker = ToolChecker("config")
        results = checker.check_all()
        print(f"  Tools: {results['available_count']}/{results['total']}")
        api_results = checker.check_api_keys()
        configured = api_results.get("configured_count", 0)
        total_api = api_results.get("total", 0)
        print(f"  API keys: {configured}/{total_api} configured")
        print(f"  AI provider: {self.args.ai}")
        print(f"  Workspace: {self.output_dir}")
        print()
        self.db.log_session_event(str(self.output_dir), {
            "event": "phase0_complete",
            "tools_available": results["available_count"],
            "api_keys_configured": configured
        })
        return True

    def run_phase(self, phase_num: int, phase_module) -> dict:
        phase_name = f"phase{phase_num}"
        print(f"\n[PHASE {phase_num}] {phase_module.NAME}")
        print("-" * 60)

        self.db.save_checkpoint(phase_name, "running")
        self.db.log_session_event(str(self.output_dir), {"event": "phase_start", "phase": phase_num})

        # Load AI overrides if available
        if self.workspace_config.exists():
            import yaml
            with open(self.workspace_config) as f:
                ai_config = yaml.safe_load(f) or {}
            phase_key = f"phase{phase_num}"
            if phase_key in ai_config:
                print(f"  [*] Using AI-configured overrides for {phase_key}")
                if hasattr(phase_module, "apply_overrides"):
                    phase_module.apply_overrides(ai_config[phase_key])

        phase_data = phase_module.run(self)

        self.db.save_checkpoint(phase_name, "completed", {
            "summary": phase_data.get("summary", {}),
        })
        self.db.log_session_event(str(self.output_dir), {
            "event": "phase_complete",
            "phase": phase_num,
            "summary": phase_data.get("summary", {})
        })

        # Update workspace metadata
        if self.workspace_meta.exists():
            with open(self.workspace_meta) as f:
                meta = json.load(f)
            completed = meta.get("phases_completed", [])
            if phase_num not in completed:
                completed.append(phase_num)
            meta["phases_completed"] = completed
            meta["status"] = f"phase_{phase_num}_done"
            with open(self.workspace_meta, "w") as f:
                json.dump(meta, f, indent=2)

        # AI analysis after each phase
        analysis = self.analyzer.analyze_phase(phase_num, phase_data)
        self.analyzer.findings["phases"][phase_name] = analysis

        # Save AI config for next phase if generated
        ai_config_next = None
        for key in ["phase2_config", "phase3_config", "phase4_config"]:
            if key in analysis:
                ai_config_next = analysis[key]
                break

        if ai_config_next:
            import yaml
            existing = {}
            if self.workspace_config.exists():
                with open(self.workspace_config) as f:
                    existing = yaml.safe_load(f) or {}
            existing[f"phase{phase_num+1}"] = ai_config_next
            with open(self.workspace_config, "w") as f:
                yaml.dump(existing, f)

        elapsed = time.time() - self.start_time
        recs = analysis.get("recommendations", [])
        if recs:
            print(f"\n  Recommendations:")
            for r in recs[:5]:
                print(f"    → {r}")

        print(f"\n  ⏱️  Elapsed: {elapsed:.0f}s")
        return phase_data

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
                print(f"  Add it to .env or config/api-keys.yaml\n")
                sys.exit(1)

        output_filename = f"{tool_name}{tool['output_ext']}"
        output_path = self.all_results_dir / output_filename

        cmd = ToolRegistry.build_cmd(tool_name, self.target, output_path, self.api_keys)
        if not cmd:
            print(f"  [!] Failed to build command\n")
            sys.exit(1)

        safe_cmd = self._scrub_sensitive(cmd[:120])
        print(f"  Running: {safe_cmd}...\n")

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
            print(f"  [!] Tool produced no output.")

        self.db.save_raw(f"single_tool_{tool_name}", result.stdout or "", output_filename)

        print(f"\n  [*] Running AI analysis on output...")
        analysis = self._analyze_single_tool(tool_name, tool, result.stdout or "", output_path)

        analysis_path = self.output_dir / "analysis" / f"single-tool-{tool_name}-analysis.txt"
        analysis_path.parent.mkdir(parents=True, exist_ok=True)
        with open(analysis_path, "w") as f:
            f.write(f"=== Single Tool Analysis: {tool_name} ===\n")
            f.write(f"Target: {self.target}\n\n")
            if analysis.get("summary"):
                for k, v in analysis["summary"].items():
                    f.write(f"{k}: {v}\n")
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

        self.db.log_session_event(str(self.output_dir), {
            "event": "single_tool_complete",
            "tool": tool_name,
            "lines": len(result.stdout.split("\n")) if result.stdout else 0,
            "success": result.returncode == 0
        })

        print(f"  [✓] Analysis: {analysis_path}\n")

    def _analyze_single_tool(self, tool_name: str, tool: dict, output: str, output_path: Path) -> dict:
        lines = [l.strip() for l in output.split("\n") if l.strip()]
        analysis = {"tool": tool_name, "summary": {"total_lines": len(lines)}, "findings": [], "recommendations": []}

        if not lines:
            return analysis

        category = tool["category"]
        if category == "subdomain":
            interesting = [l for l in lines if any(kw in l.lower() for kw in
                ["admin", "dev", "staging", "api", "test", "internal", "backup", "db", "mail"])]
            if interesting:
                analysis["findings"].append({"severity": "info", "message": f"{len(interesting)} interesting subdomains"})
                analysis["recommendations"].append("Review interesting subdomains for deeper testing")
            analysis["summary"]["total_found"] = len(lines)

        elif category == "url":
            sensitive_exts = [".sql", ".db", ".bak", ".env", ".git", ".json", ".pdf", ".xls", ".doc"]
            sensitive = [l for l in lines if any(l.lower().endswith(e) for e in sensitive_exts)]
            if sensitive:
                analysis["findings"].append({"severity": "medium", "message": f"{len(sensitive)} sensitive files"})
            analysis["summary"]["urls_with_params"] = len([l for l in lines if "=" in l])

        elif category == "vuln":
            vuln_lines = [l for l in lines if any(kw in l.lower() for kw in
                ["critical", "high", "cve-", "vuln", "xss", "sqli", "lfi", "rce", "takeover"])]
            if vuln_lines:
                analysis["findings"].append({"severity": "high", "message": f"{len(vuln_lines)} potential vulns detected"})
            analysis["summary"]["potential_vulns"] = len(vuln_lines)

        elif category == "js":
            secrets = [l for l in lines if any(kw in l.lower() for kw in
                ["api_key", "secret", "token", "password", "aws", "bucket", "slack", "firebase", "jwt"])]
            if secrets:
                analysis["findings"].append({"severity": "high", "message": f"{len(secrets)} secrets in JS"})

        elif category == "port":
            unusual = [l for l in lines if any(p in l for p in ["5432", "3306", "6379", "27017", "9200"])]
            if unusual:
                analysis["findings"].append({"severity": "medium", "message": f"Database/cache ports open"})
            analysis["summary"]["open_ports"] = len(lines)

        elif category == "dir":
            sensitive = [l for l in lines if any(kw in l.lower() for kw in
                ["admin", "backup", "config", "api", "wp-admin", "dashboard"])]
            if sensitive:
                analysis["findings"].append({"severity": "high", "message": f"Sensitive dirs: {', '.join(sensitive[:3])}"})

        return analysis

    def print_banner(self):
        banner = """
╔════════════════════════════════════════════════════╗
║              ULTIMATE RECON v1.0                   ║
║     Complete Bug Bounty Reconnaissance Toolkit     ║
╚════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"  Target:     {self.target}")
        print(f"  Workspace:  {self.output_dir}")
        print(f"  AI:         {self.args.ai}")
        print(f"  Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

    async def run(self):
        if self.args.tool:
            if not self.target:
                print("\n  [!] Target domain required when using --tool\n")
                sys.exit(1)
            self.print_banner()
            self.run_single_tool()
            self.db.close()
            return

        self.print_banner()

        if not await self.phase0_check():
            sys.exit(1)

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

        for pnum in phases_to_run:
            if pnum in phase_modules:
                if self.shutdown_flag:
                    break
                result = self.run_phase(pnum, phase_modules[pnum])

        self.analyzer.finalize()

        chains = self.analyzer.chain_vulnerabilities(
            [v for phase in self.analyzer.findings["phases"].values()
             for v in phase.get("confirmed_vulns", {}).get("high", [])
             + phase.get("confirmed_vulns", {}).get("critical", [])],
            {}
        )

        if chains:
            print(f"\n  Attack Chains Identified: {len(chains)}")
            for c in chains:
                print(f"    [{c.get('severity', '?').upper()}] {c['name']}")
                for step in c.get("steps", [])[:3]:
                    print(f"      → {step}")

        elapsed = time.time() - self.start_time
        self.db.log_session_event(str(self.output_dir), {
            "event": "session_complete",
            "elapsed": elapsed,
            "phases_completed": phases_to_run
        })

        print("\n" + "=" * 60)
        print("  FINAL SUMMARY")
        print("=" * 60)
        print(f"  Target:     {self.target}")
        print(f"  Time:       {elapsed:.0f}s ({elapsed/60:.1f}m)")
        print(f"  Workspace:  {self.output_dir}")
        print(f"  Report:     {self.output_dir}/report.html")
        print(f"  Chat log:   {self.output_dir}/chat.jsonl")
        print()

        self.db.close()


async def main():
    orch = Orchestrator()
    await orch.run()


if __name__ == "__main__":
    asyncio.run(main())
