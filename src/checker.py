import os
import shutil
import subprocess
import sys
from pathlib import Path

class ToolChecker:
    TOOLS = [
        "subfinder", "assetfinder", "findomain", "amass", "chaos",
        "httpx", "nuclei", "dnsx", "naabu", "alterx", "asnmap",
        "ffuf", "qsreplace", "gf", "unfurl", "anew", "hakrawler",
        "meg", "gau", "subjs", "haktrails", "gowitness", "aquatone",
        "getJS", "subzy", "urlfinder", "gospider", "rustscan", "puredns",
        "shuffledns", "dnsrecon", "dnsenum", "whatweb", "wafw00f",
        "nmap", "masscan", "sqlmap", "wpscan", "curl", "jq", "yq",
        "commix", "dirsearch", "arjun", "dalfox"
    ]

    PYTHON_TOOLS = [
        "corsy", "ssrfmap", "s3scanner", "cloud_enum",
        "waymore", "uro", "jenny", "bxss"
    ]

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.results = {"available": [], "missing": [], "errors": []}

    def check_tool(self, name: str) -> bool:
        return shutil.which(name) is not None

    def check_python_module(self, name: str) -> bool:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "show", name],
                capture_output=True, timeout=10
            )
            return True
        except Exception:
            return False

    def check_command_output(self, name: str, args: list = None) -> bool:
        try:
            cmd = [name]
            if args:
                cmd.extend(args)
            result = subprocess.run(cmd, capture_output=True, timeout=15)
            return result.returncode == 0
        except Exception:
            return False

    def check_all(self) -> dict:
        for tool in self.TOOLS:
            if self.check_tool(tool):
                self.results["available"].append(tool)
            else:
                self.results["missing"].append(tool)

        for tool in self.PYTHON_TOOLS:
            if self.check_python_module(tool):
                self.results["available"].append(tool)
            else:
                self.results["missing"].append(tool)

        self.results["total"] = len(self.TOOLS) + len(self.PYTHON_TOOLS)
        self.results["available_count"] = len(self.results["available"])
        self.results["missing_count"] = len(self.results["missing"])
        return self.results

    def check_api_keys(self) -> dict:
        api_file = self.config_dir / "api-keys.yaml"
        if not api_file.exists():
            return {"status": "no_config", "keys": {}}

        import yaml
        with open(api_file) as f:
            keys = yaml.safe_load(f) or {}

        configured = {k: bool(v) for k, v in keys.items()}
        return {
            "status": "ok",
            "keys": configured,
            "configured_count": sum(1 for v in configured.values() if v),
            "total": len(configured)
        }

    def summary(self) -> str:
        total = self.results["total"]
        avail = self.results["available_count"]
        missing = self.results["missing_count"]
        pct = (avail / total * 100) if total > 0 else 0
        return f"Tools: {avail}/{total} available ({pct:.0f}%)"

class DependencyChecker:
    @staticmethod
    def check_python_version() -> bool:
        return sys.version_info >= (3, 8)

    @staticmethod
    def check_disk_space(path: str = ".") -> tuple:
        try:
            usage = shutil.disk_usage(path)
            free_gb = usage.free / (1024**3)
            return (free_gb, free_gb > 1)
        except Exception:
            return (0, True)

    @staticmethod
    def check_network() -> bool:
        try:
            subprocess.run(
                ["curl", "-s", "--connect-timeout", "5", "https://google.com"],
                capture_output=True, timeout=10
            )
            return True
        except Exception:
            return False
