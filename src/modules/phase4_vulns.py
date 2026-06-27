import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

class Phase4:
    NAME = "Vulnerability Discovery — Full Attack Surface"

    def run(self, orch) -> dict:
        target = orch.target
        out = orch.output_dir
        raw = orch.all_results_dir
        db = orch.db
        stealth = orch.args.stealth
        config = orch.config.get("phases", {}).get("phase4", {})

        results = {"vulnerabilities": []}
        vulns_dir = out / "vulns"
        vulns_dir.mkdir(exist_ok=True)

        live_file = raw / "live-list.txt"
        urls_file = raw / "all-urls.txt"

        if not live_file.exists() or not live_file.stat().st_size:
            with open(live_file, "w") as f:
                f.write(f"https://{target}\n")
        if not urls_file.exists() or not urls_file.stat().st_size:
            with open(urls_file, "w") as f:
                f.write(f"https://{target}\n")

        param_sqli = raw / "params-sqli.txt"
        param_xss = raw / "params-xss.txt"
        param_lfi = raw / "params-lfi.txt"
        param_ssrf = raw / "params-ssrf.txt"
        param_redirect = raw / "params-redirect.txt"

        print("  [*] Phase 4: Parallel vulnerability scanning launched")
        print()

        vuln_futures = {}
        vuln_results = {}

        with ThreadPoolExecutor(max_workers=12) as executor:
            vm = {}

            vm[executor.submit(self._nuclei_scan, orch, live_file, vulns_dir)] = "nuclei"

            if param_sqli.exists() and param_sqli.stat().st_size:
                vm[executor.submit(self._sqli_test, orch, param_sqli, vulns_dir)] = "sqli"

            if param_xss.exists() and param_xss.stat().st_size:
                vm[executor.submit(self._xss_test, orch, param_xss, vulns_dir)] = "xss"

            if param_lfi.exists() and param_lfi.stat().st_size:
                vm[executor.submit(self._lfi_test, orch, param_lfi, vulns_dir)] = "lfi"

            if param_ssrf.exists() and param_ssrf.stat().st_size:
                vm[executor.submit(self._ssrf_test, orch, param_ssrf, vulns_dir)] = "ssrf"

            if param_redirect.exists() and param_redirect.stat().st_size:
                vm[executor.submit(self._redirect_test, orch, param_redirect, vulns_dir)] = "redirect"

            vm[executor.submit(self._cors_test, orch, live_file, vulns_dir)] = "cors"
            vm[executor.submit(self._takeover_test, orch, vulns_dir)] = "takeover"
            vm[executor.submit(self._git_leak_test, orch, live_file, vulns_dir)] = "git_leaks"

            if not stealth:
                vm[executor.submit(self._wordpress_test, orch, live_file, vulns_dir)] = "wordpress"

            for f in as_completed(vm):
                name = vm[f]
                try:
                    result = f.result()
                    vuln_results[name] = result
                except Exception as e:
                    vuln_results[name] = {"error": str(e)}

        for name, result in vuln_results.items():
            if result and "vulns" in result:
                results["vulnerabilities"].extend(result["vulns"])
                if result.get("output_file"):
                    print(f"    -> {name}: {len(result['vulns'])} findings -> {result['output_file']}")

        if not results["vulnerabilities"]:
            print("  [*] No vulnerabilities found via targeted params. Running broad nuclei on all hosts...")
            broad_nuclei = orch.run_command(
                f"cat {live_file} | nuclei -silent -c {orch.args.threads} -bs 50 "
                f"-s critical,high,medium -o {vulns_dir / 'nuclei-broad.txt'} 2>/dev/null",
                600
            )
            if (vulns_dir / "nuclei-broad.txt").exists():
                with open(vulns_dir / "nuclei-broad.txt") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            results["vulnerabilities"].append({
                                "type": "nuclei",
                                "severity": "medium",
                                "evidence": line,
                                "source": "nuclei-broad"
                            })

        for v in results["vulnerabilities"]:
            db.add_finding(
                target_id=1,
                ftype=v.get("type", "unknown"),
                severity=v.get("severity", "info"),
                url=v.get("url"),
                parameter=v.get("parameter"),
                payload=v.get("payload"),
                evidence=v.get("evidence", "")[:500],
                description=v.get("description"),
                verified=v.get("verified", False)
            )

        db.save_raw("vulnerabilities", json.dumps(results["vulnerabilities"], indent=2), "all-vulns.txt")

        results["summary"] = {
            "total_vulns": len(results["vulnerabilities"]),
            "by_severity": {
                "critical": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "critical"),
                "high": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "high"),
                "medium": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "medium"),
                "low": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "low"),
            }
        }

        def analyze_fn(phase_data):
            from src.analyzer import ReconAnalyzer
            analyzer = ReconAnalyzer(str(out), target)
            return analyzer.analyze_phase4(phase_data)

        self.analyze_fn = analyze_fn

        return results

    def _nuclei_scan(self, orch, live_file, vulns_dir):
        outfile = vulns_dir / "nuclei-results.txt"
        result = orch.run_command(
            f"cat {live_file} | nuclei -silent -c {orch.args.threads} -bs 50 "
            f"-s critical,high,medium -o {outfile} 2>/dev/null",
            600
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "nuclei",
                            "severity": "high",
                            "evidence": line,
                            "source": "nuclei"
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _sqli_test(self, orch, param_file, vulns_dir):
        outfile = vulns_dir / "sqli.txt"
        result = orch.run_command(
            f"cat {param_file} | qsreplace \"' OR '1'='1\" | httpx -silent -ms \"error|sql|syntax|mysql|oracle|postgresql\" 2>/dev/null "
            f"| tee {outfile}",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "SQL Injection",
                            "severity": "critical",
                            "url": line,
                            "parameter": "multiple",
                            "payload": "' OR '1'='1",
                            "evidence": "Error-based SQL pattern detected",
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _xss_test(self, orch, param_file, vulns_dir):
        outfile = vulns_dir / "xss.txt"
        result = orch.run_command(
            f"cat {param_file} | qsreplace '\"><script>confirm(1)</script>' | httpx -silent -ms \"confirm(1)\" 2>/dev/null "
            f"| tee {outfile}",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "severity": "high",
                            "url": line,
                            "parameter": "reflected",
                            "payload": '\"><script>confirm(1)</script>',
                            "evidence": "Payload reflected in response",
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _lfi_test(self, orch, param_file, vulns_dir):
        outfile = vulns_dir / "lfi.txt"
        result = orch.run_command(
            f"cat {param_file} | qsreplace \"/etc/passwd\" | xargs -I% -P 25 sh -c 'curl -s \"%\" 2>/dev/null | grep -q \"root:x\" && echo \"%\"' 2>/dev/null "
            f"| tee {outfile}",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "Local File Inclusion (LFI)",
                            "severity": "high",
                            "url": line,
                            "parameter": "file",
                            "payload": "/etc/passwd",
                            "evidence": "root:x found in response",
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _ssrf_test(self, orch, param_file, vulns_dir):
        outfile = vulns_dir / "ssrf.txt"
        result = orch.run_command(
            f"cat {param_file} | qsreplace \"http://169.254.169.254/latest/meta-data/\" | httpx -silent -ms \"ami-id\" 2>/dev/null "
            f"| tee {outfile}",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "Server-Side Request Forgery (SSRF)",
                            "severity": "critical",
                            "url": line,
                            "parameter": "url",
                            "payload": "http://169.254.169.254/latest/meta-data/",
                            "evidence": "Cloud metadata accessible",
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _redirect_test(self, orch, param_file, vulns_dir):
        outfile = vulns_dir / "open-redirect.txt"
        result = orch.run_command(
            f"cat {param_file} | qsreplace \"https://evil.com\" | httpx -silent -fr -mr \"evil.com\" 2>/dev/null "
            f"| tee {outfile}",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "Open Redirect",
                            "severity": "medium",
                            "url": line,
                            "parameter": "redirect",
                            "payload": "https://evil.com",
                            "evidence": "Redirect to external domain",
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _cors_test(self, orch, live_file, vulns_dir):
        outfile = vulns_dir / "cors.txt"
        result = orch.run_command(
            f"cat {live_file} | corsy -t 10 -o {outfile} 2>/dev/null",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line and "misconfig" in line.lower():
                        vulns.append({
                            "type": "CORS Misconfiguration",
                            "severity": "medium",
                            "evidence": line,
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _takeover_test(self, orch, vulns_dir):
        outfile = vulns_dir / "takeover.txt"
        subs_file = orch.all_results_dir / "final-subdomains.txt"
        if not subs_file.exists() or not subs_file.stat().st_size:
            return {"vulns": [], "output_file": str(outfile)}

        result = orch.run_command(
            f"subzy run --targets {subs_file} --concurrency 100 --hide_fails --verify_ssl 2>/dev/null | tee {outfile}",
            600
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    if "VULNERABLE" in line or "TAKEOVER" in line.upper():
                        vulns.append({
                            "type": "Subdomain Takeover",
                            "severity": "high",
                            "evidence": line.strip(),
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _git_leak_test(self, orch, live_file, vulns_dir):
        outfile = vulns_dir / "git-leaks.txt"
        result = orch.run_command(
            f"cat {live_file} | httpx -silent -path /.git/config -mc 200 -ms '[core]' 2>/dev/null | tee {outfile}",
            300
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "Git Repository Disclosure",
                            "severity": "high",
                            "url": line,
                            "evidence": "/.git/config accessible",
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}

    def _wordpress_test(self, orch, live_file, vulns_dir):
        outfile = vulns_dir / "wordpress.txt"
        result = orch.run_command(
            f"cat {live_file} | nuclei -silent -t ~/nuclei-templates/http/cves/ -tags wordpress -c 30 2>/dev/null "
            f"| tee {outfile}",
            600
        )
        vulns = []
        if outfile.exists():
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vulns.append({
                            "type": "WordPress Vulnerability",
                            "severity": "high",
                            "evidence": line,
                            "verified": False
                        })
        return {"vulns": vulns, "output_file": str(outfile)}
