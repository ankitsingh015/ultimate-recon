import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

class Phase2:
    NAME = "Live Hosts, URLs & Tech Fingerprinting"

    def run(self, orch) -> dict:
        target = orch.target
        out = orch.output_dir
        raw = orch.all_results_dir
        db = orch.db
        stealth = orch.args.stealth

        results = {
            "live_hosts": [],
            "urls": [],
            "screenshots": [],
            "tech_stack": {},
            "waf": []
        }

        subdomain_file = raw / "final-subdomains.txt"
        if not subdomain_file.exists():
            subdomain_file = raw / "all-subdomains.txt"
        if not subdomain_file.exists():
            print("  [!] No subdomains found. Using target directly.", flush=True)
            with open(subdomain_file, "w") as f:
                f.write(target + "\n")

        config = orch.config.get("phases", {}).get("phase2", {})
        ports = config.get("httpx_ports", "80,443,8080,8000,8888,8443,3000,5000")

        print("  [*] Probing live hosts with httpx...", flush=True)
        alive_file = raw / "alive-hosts.txt"
        httpx_result = orch.run_command(
            f"cat {subdomain_file} | httpx -silent -ports {ports} -threads {orch.args.threads} "
            f"-status-code -title -tech-detect -content-type -web-server -location -o {alive_file} 2>/dev/null",
            600
        )
        live_hosts = []
        if alive_file.exists():
            with open(alive_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split()
                        if parts:
                            live_hosts.append(parts[0])
            results["live_hosts"] = live_hosts
            db.save_raw("live_hosts", "\n".join(live_hosts), "alive-hosts.txt")
            print(f"    -> {len(live_hosts)} live hosts found", flush=True)

        if not live_hosts:
            print("  [!] No live hosts. Trying single target...", flush=True)
            httpx_single = orch.run_command(
                f"echo {target} | httpx -silent -ports {ports} -status-code -title -tech-detect -o {alive_file} 2>/dev/null",
                120
            )
            if alive_file.exists():
                with open(alive_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            live_hosts.append(line.split()[0])
                results["live_hosts"] = live_hosts

        live_list = raw / "live-list.txt"
        with open(live_list, "w") as f:
            f.write("\n".join(live_hosts))

        print("  [*] Collecting URLs (passive + active in parallel)...", flush=True)
        urls_file = raw / "all-urls.txt"
        task_futures = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            task_futures[executor.submit(orch.run_command,
                f"cat {live_list} | gau --mc 200 --threads {orch.args.threads} 2>/dev/null | sort -u > {raw}/gau_urls.txt", 600)] = "gau"

            task_futures[executor.submit(orch.run_command,
                f"cat {live_list} | waymore -mode U -oI {raw}/waymore_urls.txt 2>/dev/null; cat {raw}/waymore_urls.txt 2>/dev/null || echo ''", 600)] = "waymore"

            task_futures[executor.submit(orch.run_command,
                f"cat {live_list} | katana -silent -d 2 -kf -jc -o {raw}/katana_urls.txt 2>/dev/null", 600)] = "katana"

            task_futures[executor.submit(orch.run_command,
                f"cat {live_list} | gospider -S - -t 5 -d 1 --sitemap --robots -q 2>/dev/null | tee {raw}/gospider_urls.txt", 600)] = "gospider"

            task_futures[executor.submit(orch.run_command,
                f"cat {live_list} | hakrawler -subs -u -t {orch.args.threads} 2>/dev/null | sort -u > {raw}/hakrawler_urls.txt", 600)] = "hakrawler"

            for task_future in as_completed(task_futures):
                name = task_futures[task_future]
                try:
                    task_future.result()
                    print(f"    -> {name} completed", flush=True)
                except Exception as e:
                    print(f"    -> {name} failed: {e}", flush=True)

        print("  [*] Merging and deduplicating URLs...", flush=True)
        all_urls = set()
        for url_file in ["gau_urls.txt", "waymore_urls.txt", "katana_urls.txt", "gospider_urls.txt", "hakrawler_urls.txt"]:
            fp = raw / url_file
            if fp.exists():
                with open(fp) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            all_urls.add(line)

        urlfinder_result = orch.run_command(
            f"urlfinder -d {target} -silent 2>/dev/null | sort -u", 300
        )
        if urlfinder_result.stdout:
            for line in urlfinder_result.stdout.split("\n"):
                line = line.strip()
                if line:
                    all_urls.add(line)

        all_urls = sorted(all_urls)
        db.save_raw("urls", "\n".join(all_urls), "all-urls.txt")
        results["urls"] = all_urls
        print(f"    -> {len(all_urls)} unique URLs collected", flush=True)

        print("  [*] Tech fingerprinting...", flush=True)
        tech_out = raw / "tech-stack.txt"
        tech_result = orch.run_command(
            f"cat {live_list} | head -50 | whatweb -a 3 --log-verbose={tech_out} 2>/dev/null", 300
        )
        tech_stack = {}
        if tech_out.exists():
            with open(tech_out) as f:
                for line in f:
                    if "[" in line:
                        parts = line.split("[")
                        if len(parts) > 1:
                            tech_str = parts[-1].rstrip("]").strip()
                            techs = [t.strip().split(",")[0].strip() for t in tech_str.split(",") if t.strip()]
                            for t in techs:
                                tech_stack[t] = tech_stack.get(t, 0) + 1
        results["tech_stack"] = tech_stack
        db.save_raw("tech_stack", json.dumps(tech_stack, indent=2), "tech-stack.json")

        print("  [*] WAF detection...", flush=True)
        waf_result = orch.run_command(
            f"cat {live_list} | head -20 | wafw00f -i - 2>/dev/null | tee {raw}/waf-output.txt", 300
        )
        waf_results = []
        waf_file = raw / "waf-output.txt"
        if waf_file.exists():
            with open(waf_file) as f:
                for line in f:
                    if "WAF" in line or "waf" in line.lower():
                        waf_results.append(line.strip())
        results["waf"] = waf_results

        if not stealth:
            print("  [*] Taking screenshots (up to 100 hosts)...", flush=True)
            screenshot_dir = out / "screenshots"
            screenshot_dir.mkdir(exist_ok=True)
            gowitness_result = orch.run_command(
                f"cat {live_list} | head -100 | gowitness file -f - -P {screenshot_dir} --disable-db 2>/dev/null",
                300
            )
            screenshots = list(screenshot_dir.glob("*.png"))
            results["screenshots"] = [str(s.relative_to(out)) for s in screenshots[:20]]
            print(f"    -> {len(screenshots)} screenshots taken", flush=True)

        results["summary"] = {
            "live_hosts": len(live_hosts),
            "urls": len(all_urls),
            "tech_stack": len(tech_stack),
            "screenshots": len(results.get("screenshots", []))
        }

        return results

