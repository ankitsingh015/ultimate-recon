import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

class ToolInstaller:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.system = platform.system().lower()
        self.distro = self._detect_distro()
        self.install_log = []

    def _detect_distro(self) -> str:
        if self.system == "linux":
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            return line.strip().split("=")[1].strip('"')
            except Exception:
                pass
        return self.system

    def _log(self, msg: str):
        self.install_log.append(msg)
        if self.verbose:
            print(f"  [*] {msg}")

    def _run(self, cmd: list, check: bool = False) -> bool:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0 and self.verbose:
                print(f"  [!] {result.stderr[:200]}")
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self._log(f"Timeout: {' '.join(cmd)}")
            return False
        except Exception as e:
            self._log(f"Error: {e}")
            return False

    def install_go(self) -> bool:
        if shutil.which("go"):
            self._log("Go already installed")
            return True
        self._log("Installing Go...")
        if self.system == "linux":
            return self._run(["apt-get", "install", "-y", "golang-go"])
        elif self.system == "darwin":
            return self._run(["brew", "install", "go"])
        return False

    def install_python_packages(self, packages: list) -> bool:
        for pkg in packages:
            if self._run([sys.executable, "-m", "pip", "install", "--upgrade", pkg]):
                self._log(f"Installed Python package: {pkg}")
        return True

    def install_go_tool(self, path: str) -> bool:
        tool_name = path.split("/")[-1].split("@")[0]
        if shutil.which(tool_name):
            self._log(f"{tool_name} already installed")
            return True
        self._log(f"Installing {tool_name}...")
        return self._run(["go", "install", "-v", path])

    def install_system_package(self, name: str) -> bool:
        if shutil.which(name):
            self._log(f"{name} already installed")
            return True
        self._log(f"Installing system package: {name}...")
        if self.distro in ("kali", "debian", "ubuntu"):
            return self._run(["apt-get", "install", "-y", name])
        elif self.distro == "darwin":
            return self._run(["brew", "install", name])
        return False

    def install_git_repo(self, url: str, dest: str) -> bool:
        if Path(dest).exists():
            self._log(f"Repository already exists at {dest}")
            return True
        self._log(f"Cloning {url}...")
        return self._run(["git", "clone", "--depth", "1", url, dest])

    def install_nuclei_templates(self) -> bool:
        self._log("Updating nuclei templates...")
        return self._run(["nuclei", "-update-templates"])

    def install_all(self) -> dict:
        results = {"success": [], "failed": [], "skipped": []}

        go_tools = [
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/tomnomnom/assetfinder@latest",
            "github.com/findomain/findomain@latest",
            "github.com/owasp-amass/amass/v4/...@master",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
            "github.com/projectdiscovery/alterx/cmd/alterx@latest",
            "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
            "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
            "github.com/tomnomnom/qsreplace@latest",
            "github.com/tomnomnom/gf@latest",
            "github.com/tomnomnom/unfurl@latest",
            "github.com/tomnomnom/anew@latest",
            "github.com/tomnomnom/hakrawler@latest",
            "github.com/tomnomnom/meg@latest",
            "github.com/lc/gau/v2/cmd/gau@latest",
            "github.com/lc/subjs@latest",
            "github.com/hakluke/hakrawler@latest",
            "github.com/hakluke/haktrails@latest",
            "github.com/sensepost/gowitness@latest",
            "github.com/michenriksen/aquatone@latest",
            "github.com/gwen001/github-subdomains@latest",
            "github.com/incogbyte/shosubgo@latest",
            "github.com/003random/getJS@latest",
            "github.com/pentestpad/subzy@latest",
            "github.com/KathanP19/urlfinder@latest",
            "github.com/Josue87/gospider@latest",
            "github.com/s0md3v/rustscan@latest",
            "github.com/d3mondev/puredns/v2@latest",
        ]

        system_packages = [
            "nmap", "masscan", "dnsutils", "curl", "wget", "git",
            "python3", "python3-pip", "jq", "whatweb", "wafw00f",
            "sqlmap", "wpscan", "ffuf", "commix"
        ]

        python_packages = [
            "requests", "beautifulsoup4", "lxml", "jinja2", "pyyaml",
            "aiohttp", "aiofiles", "tqdm", "colorama", "rich",
            "arjun", "dalfox", "uro", "dirsearch", "gf"
        ]

        try:
            self.install_go()
            for tool in system_packages:
                if self.install_system_package(tool):
                    results["success"].append(tool)
                else:
                    results["failed"].append(tool)

            self.install_python_packages(python_packages)

            for tool in go_tools:
                if self.install_go_tool(tool):
                    results["success"].append(tool)
                else:
                    results["failed"].append(tool)

            self.install_git_repo(
                "https://github.com/danielmiessler/SecLists.git",
                "/usr/share/seclists"
            )
            self.install_git_repo(
                "https://github.com/coffinxp/payloads.git",
                "/opt/payloads"
            )
            self.install_git_repo(
                "https://github.com/coffinxp/nuclei-templates.git",
                "/root/nuclei-templates"
            )
            self.install_nuclei_templates()

        except Exception as e:
            self._log(f"Installation error: {e}")

        return results

    def get_log(self) -> str:
        return "\n".join(self.install_log)
